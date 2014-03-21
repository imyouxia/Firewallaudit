#define MAX_FILE_SIZE 8096
#define BUF_SIZE 256


int  read_profile_string(
                         const   char   * section,  
                         const   char   * key, 
                         char   ** value,   
												 char  * default_value,
                         const   char   * buf);

int  read_profile_int(const  char *section,
                      const  char  *key, 
                      int idefault_value,  
                      const char *buf);

int load_ini_file(const  char * file,  char * buf);
