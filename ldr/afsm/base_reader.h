class fsm_base_reader
{
  public:
   fsm_base_reader();
   virtual ~fsm_base_reader();
  protected:
   int is_comment(char *str);
   char *read_string(size_t &size);
   char *trim_left(char *);
   char *next_token(char *);
   void trim_right(char *);

   FILE *m_fp;
   DWORD m_line;
   size_t m_alloced;
   char *m_ptr;
};
