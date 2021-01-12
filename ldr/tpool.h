#pragma once

template <typename R>
class thread_pool
{
  public:
    using job = std::packaged_task<R()>;

    thread_pool(int i)
      : m_threads(i)
    {
      stop = false;
      for (int index = 0; index < i; index++)
        m_threads[index] = std::thread(thread_func, this);
    }
    ~thread_pool()
    {
      stop = true;
      cv.notify_all();
      for (auto& td : m_threads)
        td.join();
    }
    std::future<R> add(job &j)
    {
      std::future<R> res = j.get_future();
      std::unique_lock<std::mutex> lock(m);
      jobs.push(std::move(j));
      cv.notify_one();
      return res;
    }
  protected:
    // ripped from https://stackoverflow.com/questions/15252292/extend-the-life-of-threads-with-synchronization-c11
    static void thread_func(thread_pool *pData)
    {
      std::unique_lock<std::mutex> l(pData->m, std::defer_lock);
      while (true)
      {
        l.lock();
        pData->cv.wait(l, [pData] () {
           return (pData->stop || !pData->jobs.empty()); 
        });
        if (pData->stop)
          return;
        job j = std::move(pData->jobs.front());
        pData->jobs.pop();

        l.unlock();
        j();
      }
    }
    std::queue<job> jobs;
    std::condition_variable cv;
    std::mutex m;
    std::vector<std::thread> m_threads;
    bool stop;
};