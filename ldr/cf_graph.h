#pragma once

#include <algorithm> 

template <typename T>
class code_area
{
 public:
  code_area(code_area &&) = default;
  code_area(const code_area &)  = default;
  explicit code_area() : addr{}, size{} {};
  code_area(T a, size_t s) : addr(a), size(s) {};
  T addr;
  size_t size;
};

template <typename T>
int contains(std::list<code_area<T> > &list, T addr)
{
  for ( auto citer = list.cbegin(); citer != list.cend(); ++citer )
  {
    if ( (addr >= citer->addr) && (addr < (citer->addr + citer->size)) )
      return 1;
  }
  return 0;
}

template <typename T>
class graph_ranges
{
  public:
   graph_ranges() = default;
  ~graph_ranges() = default;
   // for stat
   size_t calc_size() const
   {
      size_t res = 0;
      for ( auto citer = m_ranges.cbegin(); citer != m_ranges.cend(); ++citer )
      {
        res += citer->size;
      }
      return res;
   }
   // check if we already have (processed) ranges for this addr
   int in_ranges(T addr) const
   {
    for ( auto iter = ranges.cbegin(); iter != ranges.cend(); ++iter )
      if ( (addr >= iter->addr) &&
           (addr < (iter->addr + iter->size))
         )
       return 1;
    return 0;
   }
   // ranges
   typedef std::list<code_area<T> > GRange;
   // currently added ranges - no persistent. they then will be moved to persistent m_ranges
   GRange ranges;
   void add_range(T addr, size_t size)
   {
     code_area<T> tmp{ addr, size };
     for ( auto cit = ranges.begin(); cit != ranges.end(); ++cit )
     {
       if ( interleaved(tmp, *cit) )
        return;
     }
     ranges.push_back(tmp);
   }
  protected:
   // check if we already have (processed) ranges for this addr
   int in_mranges(T addr) const
   {
    for ( auto iter = m_ranges.cbegin(); iter != m_ranges.cend(); ++iter )
      if ( (addr >= iter->addr) &&
           (addr < (iter->addr + iter->size))
         )
       return 1;
    return 0;
   }
   // add new range, possibly merge with some other
   void insert_range(const code_area<T> &ca)
   {
     for ( auto iter = m_ranges.begin(); iter != m_ranges.end(); ++iter )
       if ( interleaved(ca, *iter) )
         return;
      try
      {
        m_ranges.push_back(ca);
      } catch(std::bad_alloc)
      { }
   }
   template <typename T>
   static int inline is_inside(const code_area<T> &ca1, T end1, const code_area<T> &ca2, T end2)
   {
      return ( (ca1.addr >= ca2.addr) &&
               (ca1.addr < end2) &&
               (end1 > ca2.addr) &&
               (end1 <= end2)
             );
   }
   template <typename T>
   static int interleaved(const code_area<T> &ca, code_area<T> &our)
   {
     T end1 = ca.addr + ca.size;
     T end2 = our.addr + our.size;
     // 1) check if new range inside old
     if ( is_inside(ca, end1, our, end2) )
       return 1;
     // 2) check if old range inside new
     if ( is_inside(our, end2, ca, end1) )
     {
       our.size = ca.size;
       our.addr = ca.addr;
       return 1;
     }
     // 3) check for left edge
     if ( (end1 >= our.addr) &&
          (end1 <= end2)
        )
     {
       our.addr = ca.addr;
       our.size = end2 - our.addr;
       return 1;
     }
     // 4) check for right edge
     if ( (ca.addr >= our.addr) &&
          (ca.addr <= end2)
        )
     {
       our.size = end1 - our.addr;
       return 1;
     }
     // don`t interleaved
     return 0;
   }
   // ranges
   GRange m_ranges;
};

// just graph of code blocks, no state, so all addresses stored in simple std::set
template <typename T>
class cf_graph: public graph_ranges<T>
{
  public:
   cf_graph() = default;
  ~cf_graph() = default;
   inline int empty() const
   {
     return m_nodes.empty();
   }
   // add new node with address
   void add(T addr)
   {
     if (graph_ranges<T>::in_mranges(addr) )
      return;
     try
     {
       m_nodes.insert(addr);
     } catch(std::bad_alloc)
     { }
   }
   // return count of addresses out of range
   size_t check(T addr, size_t range)
   {
     code_area<T> ca = { addr, range };
     return check(ca);
   }
   size_t check(const code_area<T> &ca)
   {
     delete_in(ca);
     return m_nodes.size();
   }
   size_t delete_ranges(std::list<code_area<T> > *ranges)
   {
     for ( auto citer = ranges->begin(); citer != ranges->end(); ++citer )
     {
       delete_in(*citer);
       graph_ranges<T>::insert_range(*citer);
     }
     ranges->clear();
     return m_nodes.size();
   }
   size_t delete_ranges(std::list<code_area<T> > *ranges, std::list<T> *list)
   {
     delete_ranges(ranges);
     list->clear();
     try
     {
       for ( auto iter = m_nodes.cbegin(); iter != m_nodes.cend(); ++iter )
         list->push_back(*iter);
     } catch(std::bad_alloc)
     {}
     ranges->clear();
     return list->size();
   }
   size_t delete_ranges(std::list<code_area<T> > *ranges, std::vector<T> &vec)
   {
     delete_ranges(ranges);
     vec.clear();
     if ( m_nodes.empty() )
       return 0;
     try
     {
       vec.reserve(m_nodes.size());
       std::copy(m_nodes.cbegin(), m_nodes.cend(), back_inserter(vec));
     } catch(std::bad_alloc)
     {}
     // sort vector
     std::sort(vec.begin(), vec.end(), std::less<T>());
     return vec.size();
   }
   // return addresses out of range
   size_t check(T addr, size_t range, std::list<T> *list)
   {
     code_area<T> ca = { addr, range };
     return check(ca, list);
   }
   size_t check(T addr, size_t range, std::vector<T> &vec)
   {
     code_area<T> ca = { addr, range };
     return check(ca, vec);
   }
   size_t check(const code_area<T> &ca, std::list<T> *list)
   {
     delete_in(ca);
     insert_range(ca);
     list->clear();
     try
     {
       for ( auto iter = m_nodes.cbegin(); iter != m_nodes.cend(); ++iter )
         list->push_back(*iter);
     } catch(std::bad_alloc)
     {}
     return list->size();
   }
   size_t check(const code_area<T> &ca, std::vector<T> &vec)
   {
      delete_in(ca);
      insert_range(ca);
      vec.clear();
      if ( m_nodes.empty() )
        return 0;
      try
      {
         vec.reserve(m_nodes.size());
         std::copy(m_nodes.cbegin(), m_nodes.cend(), back_inserter(vec));
      } catch(std::bad_alloc)
      {}
      // sort vector
      std::sort(vec.begin(), vec.end(), std::less<T>());
      return vec.size();
   }
  protected:
   // delete addresses in some range
   void delete_in(const code_area<T> &ca)
   {
     for ( auto iter = m_nodes.begin(); iter != m_nodes.end(); )
     {
       if ( (*iter >= ca.addr) &&
            (*iter < (ca.addr + ca.size))
          )
        iter = m_nodes.erase(iter);
       else
        ++iter;
     }
   }

   // addresses
   std::set<T> m_nodes;
};

// graph with statefull edges
template <typename T, typename S>
class statefull_graph: public graph_ranges<T>
{
  public:
   statefull_graph() = default;
  ~statefull_graph() = default;
   typedef std::pair<T, S> Edge;
   int add(T addr, S state)
   {
     if (graph_ranges<T>::in_mranges(addr) )
      return 0;
     auto found = m_nodes.find(addr);
     if ( found != m_nodes.end() )
     {
       // There is a problem - when you add edge what must happens if it already was added with some other state?
       if ( found->second < state )
         found->second = state;
       return 1;
     }
     try
     {
       m_nodes[addr] = state;
     } catch(std::bad_alloc)
     { 
       return 0;
     }
     return 1;
   }
   size_t delete_ranges(std::list<code_area<T> > *ranges, std::list<Edge> *list)
   {
     delete_ranges(ranges);
     list->clear();
     if ( m_nodes.empty() )
       return 0;
     try
     {
       for ( auto iter = m_nodes.cbegin(); iter != m_nodes.cend(); ++iter )
       {
         Edge tmp { iter->first, iter->second };
         list->push_back(tmp);
       }
     } catch(std::bad_alloc)
     { }
     return list->size();
   }
   size_t delete_ranges(std::list<code_area<T> > *ranges, std::vector<Edge> &vec)
   {
     delete_ranges(ranges);
     vec.clear();
     if ( m_nodes.empty() )
       return 0;
     try
     {
        vec.reserve(m_nodes.size());
        std::copy(m_nodes.cbegin(), m_nodes.cend(), back_inserter(vec));
     } catch(std::bad_alloc)
     { }
     // sort vector
     std::sort(vec.begin(), vec.end(), [](const Edge &l, const Edge &r) -> bool { return l.first < r.first;  });
     return vec.size();
   }
  protected:
   void delete_in(const code_area<T> &ca)
   {
     for ( auto iter = m_nodes.begin(); iter != m_nodes.end(); )
     {
       if ( (iter->first >= ca.addr) &&
            (iter->first < (ca.addr + ca.size))
          )
        iter = m_nodes.erase(iter);
       else
        ++iter;
     }
   }
   size_t delete_ranges(std::list<code_area<T> > *ranges)
   {
     for ( auto citer = ranges->begin(); citer != ranges->end(); ++citer )
     {
       delete_in(*citer);
       graph_ranges<T>::insert_range(*citer);
     }
     ranges->clear();
     return m_nodes.size();
   }
   // statefull addresses
   std::map<T, S> m_nodes;
};
