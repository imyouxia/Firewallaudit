#include  <stdio.h>
#include  <stdlib.h>
#include  <assert.h>
#include  <string.h>
#include  <ctype.h>

#include  "inifile.h"
#include "constant.h"

#define  MAX_FILE_SIZE 8096

#define  LEFT_BRACE '['
#define  RIGHT_BRACE ']'
	

int load_ini_file(const  char * file,  char * buf)
{
	int  i = 0 ;
	FILE  * in = NULL;
	//*file_size = 0 ;

	assert(file  != NULL);
	assert(buf  != NULL);
	
	in = fopen(file, "r");
	if ( NULL  == in ) {
		return   FAIL;
	}
	
	// load initialization file
	while ((buf[i] = fgetc(in)) != EOF) {
		i ++ ;
		assert( i < MAX_FILE_SIZE);  // file too big
	}
	
	buf[i] = '\0';
	//*file_size  =  i;
	
	fclose(in);
	return OK;
}

static  int isnewline( char  c)
{
     return  ( '\n'   ==  c  ||    '\r'   ==  c ) ?  1  :  0 ;
}

static   int  isend( char  c)
{
     return   '\0' == c ?  1  :  0 ;
}

static   int  isleftbarce( char  c)
{
     return  LEFT_BRACE  ==  c ?   1  :  0 ;
}

static   int  isrightbrace( char  c )
{
     return  RIGHT_BRACE  ==  c ?   1  :  0 ;
}

static  int  parse_file(const   char   * section,  
                        const   char   * key,  
                        const   char   * buf, 
                        int   * sec_s, 
                        int   * sec_e,
                        int   * key_s, 
                        int   * key_e,  
                        int   * value_s,  
                        int   * value_e)
{
	const   char   * p  =  buf;
	int  i = 0 ;
	assert(buf != NULL);
	assert(section  !=  NULL  &&  strlen(section));
	assert(key  !=  NULL  &&  strlen(key));
	* sec_e  =   * sec_s  =   * key_e  =   * key_s  =   * value_s  =   * value_e  =   - 1 ;

	while(!isend(p[i]))
	{
         // find the section
		if(( 0 == i || isnewline(p[i - 1 ])) && isleftbarce(p[i]))
        {
			int  section_start = i + 1 ;

             // find the ']'
			do
            {
				i ++;
            }while( !isrightbrace(p[i]) && !isend(p[i]));

            if( 0 == strncmp(p + section_start,section, i - section_start))
            {
				int  newline_start = 0;
				i++;

                 // Skip over space char after ']'
                while (isspace(p[i]))
                {
					i++;
                }

                 // find the section
                *sec_s = section_start;
                *sec_e = i;

                while( !(isnewline(p[i - 1 ]) && isleftbarce(p[i])) && !isend(p[i]))
                {
					int  j = 0 ;
                     // get a new line
                    newline_start  =  i;

                    while( !isnewline(p[i]) && !isend(p[i]))
                    {
                        i ++ ;
                    }
                     // now i  is equal to end of the line

                    j = newline_start;

                    if(';' != p[j])  // skip over comment
                    {
                        while(j < i && p[j] != '=')
                        {
                            j ++ ;
                            if('=' == p[j])
                            {
                                if(strncmp(key,p + newline_start,j - newline_start) == 0)
                                {
                                     // find the key ok
                                	* key_s = newline_start;
                                    * key_e = j - 1;

                                    * value_s = j + 1;
                                    * value_e = i;
									if(*value_e == *value_s)
									{
										return 0;
									}
									else
									{
										return 1 ;
									}
                                }
                            }
                         }
                     }
                    i++;
                }
            }
        }
        else
        {
        	i++;
        }
    }
    return 0;
}

int  read_profile_string(
                         const   char   * section,  
                         const   char   * key, 
                         char   ** value,   
												 char  * default_value,
                         const   char   * buf)
{
	int  sec_s,sec_e,key_s,key_e, value_s, value_e;

	char temp[BUF_SIZE];
    assert(section != NULL && strlen(section));
    assert(key != NULL && strlen(key));
    assert(value != NULL);
	assert(default_value != NULL);
    assert(buf != NULL && strlen(key));


	memset(temp, 0, sizeof(temp));
	if (!parse_file(section, key, buf, &sec_s, &sec_e, &key_s, &key_e, &value_s, &value_e))
	{
		if (default_value != NULL)
		{
			strcpy(temp, default_value );
			*value = strdup(temp);
			return OK;
		}
		else
		{
			*value = NULL;
			return FAIL;
		}
	}
	else
	{

		int  cpcount  =  value_e  - value_s;

		if(sizeof(temp) - 1 < cpcount)
		{
			cpcount = sizeof(temp) - 1;
		}

		memset(temp, 0, sizeof(temp));
		memcpy(temp, buf + value_s, cpcount);
		temp[cpcount] = '\0';
		*value = strdup(temp);
		return OK;
	}
}


int  read_profile_int(const  char *section,
                      const  char  *key, 
                      int idefault_value,  
                      const char *buf)
{
	char * value;
	char default_value[BUF_SIZE];
	sprintf(default_value, "%d", idefault_value);
	if (read_profile_string(section, key, &value, default_value, buf) == FAIL)
	{
		return FAIL;
	}
	else
	{
		int retv = atoi(value);
		free(value);
		return retv; 
	}
}

