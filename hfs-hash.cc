//
// hash-all.cc
//
// Copyright (c) 2014-2015, Krister Joas
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// Calculate hashes (sha256) for files in a list of locations.  Only files
// having specific extensions are processed.  The hashes are then stored in a
// SQLite database.  Once hashes have been recorded for all files the program
// will go back and recalculate the hashes, comparing them with the previous
// result.  Any change is reported as an error.
//
// Hash calculation is done in parallel across different volumes.  However,
// files on the same volume are processed in sequence.  This is because for
// spinning disks I've found that it doesn't necessarily go any faster,
// presumably due to head movements.  If volumes are SSD the processing could
// probably be done in parallel for files on the same volume.
//
// External dependencies
//
// sqlite3pp: https://github.com/iwongu/sqlite3pp
// boost: http://www.boost.org

#include <CommonCrypto/CommonDigest.h>
#include <time.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <ctime>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <mutex>
#include <queue>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/date_time.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/optional.hpp>
#include <boost/program_options.hpp>

#include <sqlite3pp.h>

namespace fs = boost::filesystem;
namespace dt = boost::gregorian;
namespace po = boost::program_options;
namespace pt = boost::posix_time;
namespace sql = sqlite3pp;

namespace hash
{
  std::string to_hex(const std::string& hash)
  {
    static const std::string hex { "0123456789abcdef" };
    std::string h;
    for(auto i: hash)
    {
      h.push_back(hex[i >> 4 & 0xf]);
      h.push_back(hex[i & 0xf]);
    }
    return h;
  }

  std::string hash_file(const std::string& filename)
  {
    CC_SHA256_CTX c;
    CC_SHA256_Init(&c);
    char buffer[1024 * 16];
    std::ifstream f(filename, std::ios::binary);
    for(;;)
    {
      f.read(buffer, sizeof(buffer));
      if(f.gcount())
	CC_SHA256_Update(&c, buffer, f.gcount());
      else
	break;
    }
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &c);
    std::string hashstring(reinterpret_cast<const char*>(hash), CC_SHA256_DIGEST_LENGTH);
    return to_hex(hashstring);
  }
}

namespace
{
  std::string to_string(const dt::date& date)
  {
    static std::locale loc(std::locale::classic(), new dt::date_facet("%Y-%m-%d"));
    std::ostringstream os;
    os.imbue(loc);
    os << date;
    return os.str();
  }

  std::string to_string(const pt::ptime& time)
  {
    static std::locale loc(std::locale::classic(), new pt::time_facet("%Y-%m-%d %H:%M:%S"));
    std::ostringstream os;
    os.imbue(loc);
    os << time;
    return os.str();
  }

  boost::optional<std::string> get_env(const std::string& name)
  {
    auto val = getenv(name.c_str());
    if(val)
      return std::string(val);
    return boost::none;
  }
}

class Item
{
  public:
    Item(const fs::path& path, const pt::ptime& date, const std::string& hash)
      : _path(path), _date(date), _hash(hash)
    {}
    Item(const char* path, const char* date, const char* hash)
      : _path(path), _date(pt::time_from_string(date)), _hash(hash)
    {}
    explicit Item(const fs::path& path) : _path(path)
    {}
    bool operator<(const Item& other) const
    {
      return _date < other._date;
    }
    enum class Results { OK, ERROR, REMOVED, ADDED };
    // Getters and setters.
    const fs::path& path() const { return _path; };
    const pt::ptime& date() const { return _date; }
    const std::string& hash() const { return _hash; }
    Results result() const { return _result; }
    void path(const fs::path& path) { _path = path; }
    void date(const pt::ptime& date) { _date = date; }
    void hash(const std::string& h) { _hash = h; }
    void result(Results r) const { _result = r; }
    // Print the result.
    void report(unsigned count, unsigned total, bool verbose) const;
    // Convert enum Results into a string.
    static std::string to_string(Results);
  private:
    fs::path _path;
    pt::ptime _date = pt::second_clock::local_time();
    std::string _hash;
    mutable Results _result = Results::OK;
};

void Item::report(unsigned count, unsigned total, bool verbose) const
{
  if(verbose || _result != Item::Results::OK)
  {
    if(verbose)
      std::cout << boost::format("%1% [%2%/%3%] %4%\n") % to_string(_result) % count % total % _path.string();
    else
      std::cout << boost::format("%1% %2%\n") % to_string(_result) % _path.string();
  }
}

std::string Item::to_string(Results result)
{
  switch(result)
  {
    case Results::OK:
      return "OK";
    case Results::ERROR:
      return "ERROR";
    case Results::ADDED:
      return "ADDED";
    case Results::REMOVED:
      return "REMOVED";
  }
}

class Database
{
  public:
    Database(const std::string& name, bool record) : _db(name.c_str()), _record(record)
    {
      _db.execute(
	"create table if not exists digest (filename, hash, date);"
	"create unique index if not exists ix_digest on digest (filename);"
	"create table if not exists bad (filename, hash, date);"
	"create unique index if not exists ix_bad on bad (filename, hash);"
	"create table if not exists result (filename, result, hash, date)");
    }

    void load(std::multiset<Item>& items, std::map<dt::date, int>& counter)
    {
      sql::query q(_db, "select filename, date, hash from digest");
      for(auto i: q)
      {
	const char* path;
	const char* date;
	const char* hash;
	std::tie(path, date, hash) = i.get_columns<const char*, const char*, const char*>(0, 1, 2);
	Item item(path, date, hash);
	items.insert(item);
	++counter[item.date().date()];
      }
    }

    void insert(const Item& item)
    {
      sql::command cmd(_db, "insert into digest values(?, ?, ?)");
      cmd.bind(1, item.path().string().c_str());
      cmd.bind(2, item.hash().c_str());
      cmd.bind(3, ::to_string(item.date()).c_str());
      cmd.execute();
      result(item);
    }

    void update(const Item& item)
    {
      sql::command cmd(_db, "insert or replace into digest values(?, ?, ?)");
      cmd.bind(1, item.path().string().c_str());
      cmd.bind(2, item.hash().c_str());
      cmd.bind(3, ::to_string(item.date()).c_str());
      cmd.execute();
      result(item);
    }

    void remove(const fs::path& path)
    {
      sql::query q(_db, "select filename, date, hash from digest where filename = ?");
      q.bind(1, path.string().c_str());
      for(auto i: q)
      {
	const char* path;
	const char* date;
	const char* hash;
	std::tie(path, date, hash) = i.get_columns<const char*, const char*, const char*>(0, 1, 2);
	Item item(path, date, hash);
	item.result(Item::Results::REMOVED);
	item.report(0, 0, false);
	result(item);
      }
      sql::command cmd(_db, "delete from digest where filename = ?");
      cmd.bind(1, path.string().c_str());
      cmd.execute();
    }

    void bad(const Item& item)
    {
      sql::command cmd(_db,
	"insert or ignore into bad values(?, ?, ?)");
      cmd.bind(1, item.path().string().c_str());
      cmd.bind(2, item.hash().c_str());
      cmd.bind(3, ::to_string(item.date()).c_str());
      cmd.execute();
      result(item);
    }

    void list_bad()
    {
      std::multiset<Item> items;
      load_bad(items);
      for(auto i: items)
	std::cout << i.path().string() << " " << i.hash() << " "
	  << ::to_string(i.date()) << "\n";
    }

    void clear()
    {
      sql::command cmd(_db,
	"insert or replace into digest (filename, hash, date) "
        "select digest.filename, bad.hash, bad.date "
        "from bad left join digest on bad.filename = digest.filename");
      cmd.execute();
      cmd.prepare("delete from bad");
      cmd.execute();
    }
  private:
    sql::database _db;
    bool _record;

    void load_bad(std::multiset<Item>& items)
    {
      sql::query q(_db, "select filename, date, hash from bad");
      for(auto i: q)
      {
	const char* path;
	const char* date;
	const char* hash;
	std::tie(path, date, hash) = i.get_columns<const char*, const char*, const char*>(0, 1, 2);
	Item item(path, date, hash);
	items.insert(item);
      }
    }

    void result(const Item& item)
    {
      if(!_record)
	return;
      sql::command cmd(_db, "insert into result values(?, ?, ?, ?)");
      cmd.bind(1, item.path().string().c_str());
      cmd.bind(2, Item::to_string(item.result()).c_str());
      cmd.bind(3, item.hash().c_str());
      cmd.bind(4, ::to_string(item.date()).c_str());
      cmd.execute();
    }      
};

class Filescanner
{
  public:
    Filescanner() {}

    void walk(std::set<fs::path>& files)
    {
      unsigned stats(0);
      auto max_elt(std::max_element(_directories.begin(), _directories.end(),
	[](const std::string& l, const std::string& r){return l.size() < r.size();}));
      for(auto i: _directories)
      {
	walk(i, files);
	std::cout << std::setw(max_elt->size()) << std::left
	  << i << " " << (files.size() - stats) << "\n";
	stats = files.size();
      }
    }

    void directories(const std::vector<std::string>& dirs)
    {
      _directories = dirs;
    }

    void filetypes(const std::vector<std::string>& types)
    {
      std::copy(types.begin(), types.end(), std::inserter(_filetypes, _filetypes.begin()));
    }

  private:
    class icasecompare
    {
      public:
        bool operator()(const std::string& l, const std::string& r) const
	{
	  return boost::ilexicographical_compare<std::string, std::string>(l, r);
	}
    };

    // Collect all files to process.
    void walk(const fs::path& path, std::set<fs::path>& files)
    {
      if(!fs::exists(path))
	return;
      std::copy_if(fs::recursive_directory_iterator(path), fs::recursive_directory_iterator(),
	std::inserter(files, files.end()), [this](const fs::path& p){return match(p);});
    }

    // Returns true for files we're interested in.
    bool match(const fs::path& path)
    {
      if(!fs::is_regular(path))
	return false;
      if(path.filename().string()[0] == '.')
	return false;
      if(_filetypes.count(path.extension().string()))
	return true;
      return false;
    }

    std::vector<std::string> _directories;
    std::set<std::string, icasecompare> _filetypes;
};

class QueueManager
{
  public:
    QueueManager(const std::vector<std::string>& scan_dirs, Database& db) : _db(db)
    {
      for(auto i: scan_dirs)
      {
	fs::path path{i};
	std::string name{find_name(path)};
	auto k = _queues.find(name);
	if(k == _queues.end())
	  _queues.insert(queue_t::value_type(name, std::unique_ptr<Queue>(new Queue(name, *this))));
      }
    }

    void push_back(const Item& item)
    {
      std::string name{find_name(item.path())};
      auto k = _queues.find(name);
      k->second->push(item);
      ++_count;
    }

    void start(bool verbose, bool dry)
    {
      // Start the queues' worker threads.
      std::vector<std::future<void>> tasks;
      for(auto& i: _queues)
	tasks.push_back(std::async([&i](){i.second->worker();}));
      // Read and report the results.
      consumer(_count, verbose, dry);
    }

    // Total number of items in all the work queues.
    unsigned count() const { return _count; }
    using value_type = Item;	// Needed for back_inserter.
  private:
    class Queue
    {
      public:
	Queue(const std::string name, QueueManager& manager)
	  : _name(name), _manager(manager)
	{
	  manager.add_queue();
	}
	const std::string& name() const { return _name; }
	void push(Item item) { _work_queue.push(item); }
	bool empty() const { return _work_queue.empty(); }
	void worker();
      private:
	std::queue<Item> _work_queue;
	const std::string _name;
	QueueManager& _manager;
    };

    void consumer(unsigned total, bool verbose, bool dry);
    void add_queue() { _done.fetch_add(1); }
    void remove_queue() { _done.fetch_sub(1); }
    void notify_one() { _queue_cv.notify_one(); }
    void notify_all() { _queue_cv.notify_all(); }
    void push_result(const Item& item)
    {
      std::lock_guard<std::mutex> lg(_mutex);
      _result_queue.push(item);
    }

    std::string find_name(const fs::path& path)
    {
      std::vector<std::string> v;
      for(auto k: path)
	v.push_back(k.string());
      if(v.size() > 3 && v[1] == "Volumes")
	return v[2];
      return std::string("Other");
    }

    // Create a queue for each volume.
    using queue_t = std::map<std::string, std::unique_ptr<Queue>>;
    queue_t _queues;
    Database& _db;
    unsigned _count{0};
    std::mutex _mutex;
    std::condition_variable _queue_cv;
    std::queue<Item> _result_queue;
    std::atomic<int> _done{0};
};

void QueueManager::consumer(unsigned total, bool verbose, bool dry)
{
  unsigned count{0};
  while(true)
  {
    std::unique_lock<std::mutex> ul(_mutex);
    _queue_cv.wait(ul, [this]{return !_result_queue.empty() || _done.load() == 0;});
    if(_done.load() == 0 && _result_queue.empty())
      return;
    auto& item = _result_queue.front();
    ++count;
    if(!dry)
    {
      switch(item.result())
      {
	case Item::Results::ADDED:
	  _db.insert(item);
	  break;
	case Item::Results::ERROR:
	  _db.bad(item);
	  break;
	case Item::Results::OK:
	  _db.update(item);
	  break;
	case Item::Results::REMOVED:
	  break;
      }
    }
    item.report(count, total, verbose);
    _result_queue.pop();
  }
}

void QueueManager::Queue::worker()
{
  while(!_work_queue.empty())
  {
    Item& item = _work_queue.front();
    std::string old_hash{item.hash()};
    item.hash(hash::hash_file(item.path().string()));
    item.date(pt::second_clock::local_time());
    if(old_hash.empty())
      item.result(Item::Results::ADDED);
    else if(old_hash != item.hash())
      item.result(Item::Results::ERROR);
    _manager.push_result(item);
    _work_queue.pop();
    _manager.notify_one();
  }
  _manager.remove_queue();
  _manager.notify_all();
}

int main(int argc, const char** argv)
{
  po::options_description cmdline{"Usage"};
  fs::path home{*get_env("HOME")};
  std::string config_file;
  fs::path default_config_file{home};
  default_config_file /= ".hfs-hash.rc";
  // Command line only options.
  cmdline.add_options()
    ("bad,b", "list files which has a hash which differs from the one recorded")
    ("config,c", po::value(&config_file)->default_value(default_config_file.string()))
    ("dry,n", "dry run, don't update the database")
    ("help,h", "print help message")
    ("update,u", "update error hashes and clear the list of bad files")
    ("verbose,v", "verbose output, print each file processed")
    ;

  fs::path dbfile_path{home};
  dbfile_path /= ".sha256.db";
  std::string dbfile{dbfile_path.string()};
  unsigned long max{1500};
  std::vector<std::string> scan_dirs;
  std::vector<std::string> file_types;
  po::options_description config{"Config"};
  // Command line and config file options.
  config.add_options()
    ("database,d", po::value(&dbfile)->default_value(dbfile), "path to SQLite3 database file")
    ("max,m", po::value(&max)->default_value(max), "set maximum number of files to process")
    ("record", "record every action")
    ("scan,s", po::value(&scan_dirs), "directories to scan")
    ("type,t", po::value(&file_types), "file extensions to process.")
    ;

  po::options_description options;
  options.add(cmdline).add(config);

  po::variables_map vm;

  // Parse command line and config options.
  try
  {
    po::store(po::command_line_parser(argc, argv).options(options).run(), vm);
    po::notify(vm);
  }
  catch(const po::error& e)
  {
    std::cerr << "error: " << e.what() << "\n";
    std::cerr << options;
    return 1;
  }
  
  if(vm.count("help"))
  {
    std::cout << options;
    return 0;
  }

  // Read and parse config file, if any.
  if(!config_file.empty())
  {
    std::ifstream in(config_file);
    if(!in)
    {
      std::cerr << "can't open file: " << config_file << "\n";
      return 1;
    }
    try
    {
      po::store(po::parse_config_file(in, config), vm);
      notify(vm);
    }
    catch(const po::error& e)
    {
      std::cerr << "error: " << e.what() << "\n";
      std::cerr << config;
      return 1;
    }
  }

  bool record(vm.count("record"));
  Database db(dbfile, record);
  if(vm.count("update"))
  {
    db.clear();
    return 0;
  }

  if(vm.count("bad"))
  {
    db.list_bad();
    return 0;
  }

  bool dry(vm.count("dry"));
  bool verbose(vm.count("verbose"));

  // Find all files in the directories, matching a list of file types, to
  // process.
  std::set<fs::path> files;
  Filescanner f;
  f.directories(scan_dirs);
  f.filetypes(file_types);
  f.walk(files);

  // Get all the files already in the database.
  std::multiset<Item> items;
  std::map<dt::date, int> counter;
  db.load(items, counter);

  // Put all the paths into a collection on which we can do set operations.
  std::set<fs::path> dbfiles;
  std::transform(items.begin(), items.end(), std::inserter(dbfiles, dbfiles.end()),
    [](const Item& x) {return x.path();});

  // Added files.
  std::set<fs::path> added;
  std::set_difference(files.begin(), files.end(), dbfiles.begin(), dbfiles.end(),
    std::inserter(added, added.end()));
  // Removed files.
  std::set<fs::path> removed;
  std::set_difference(dbfiles.begin(), dbfiles.end(), files.begin(), files.end(),
    std::inserter(removed, removed.end()));

  // Print a summary of the number of files and number of files per date in the
  // database.
  boost::format fmt{"%|-13|%|-8|\n"};
  std::cout << fmt % "files:" % files.size();
  std::cout << fmt % "database:" % dbfiles.size();
  std::cout << fmt % "add:" % added.size();
  std::cout << fmt % "remove:" % removed.size();
  std::cout << fmt % "check:" % max;
  for(auto i: counter)
    std::cout << fmt % to_string(i.first) % i.second;

  // Process: First delete files removed from the file system.
  if(max > 0 && !dry)
    for(auto i: removed)
      db.remove(i);

  QueueManager manager(scan_dirs, db);
  // Add files which have been added since previous run.
  if(!added.empty())
  {
    // Randomize the order in which we add new files.
    std::vector<fs::path> randomize;
    randomize.resize(added.size());
    std::copy(added.begin(), added.end(), randomize.begin());
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::shuffle(randomize.begin(), randomize.end(), std::default_random_engine(seed));
    std::copy_n(
      boost::make_transform_iterator(randomize.begin(), [](const fs::path& p) { return Item(p); }),
      std::min(max, randomize.size()),
      std::back_inserter(manager));
  }
  // Add items for existing hashes, oldest first.
  if(manager.count() < max)
  {
    // Use a filter_iterator to filter out any path which has been deleted.
    std::copy_n(
      boost::make_filter_iterator(
	[&removed](const Item& item){return !removed.count(item.path());},
	items.begin(), items.end()),
      std::min(max - manager.count(), items.size() - removed.size()),
      std::back_inserter(manager));
  }
  manager.start(verbose, dry);

  // Finally, print the list of files with bad hashes, if any.
  db.list_bad();

  return 0;
}
