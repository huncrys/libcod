#include "gsc_utils.hpp"

#if COMPILE_UTILS == 1

#include <dirent.h> // dir stuff
#include <assert.h>
#include <ctype.h> // toupper
#include <ctime> // time, strftime, strptime
#include <iostream> // std::string

#define MAX_LANGUAGES 16
#define MAX_LANGUAGE_ITEMS 1024

// 1.2 0x080F6D5A
int utils_hook_player_eject(int player)   // player 0 = 0x08679380 + 0x11c = 0x0867949c
{
	//printf("int hook_player_eject(int player=%.8x)\n", player);
	return 0;
}

int languages_defined = 0;
int language_items_defined = 0;
char languages[MAX_LANGUAGES][3]; //add space for \0
char *language_items[MAX_LANGUAGE_ITEMS];
char *language_references[MAX_LANGUAGES][MAX_LANGUAGE_ITEMS];
bool language_reference_mallocd[MAX_LANGUAGES][MAX_LANGUAGE_ITEMS];

void gsc_add_language()
{
	char *str;
	if(!stackGetParamString(0, &str))
	{
		printf("Param 0 needs to be a string for add_language\n");
		stackPushUndefined();
		return;
	}
	if(str[0] == '\0' || str[1] == '\0' || str[2] != '\0')
	{
		printf("Languages are defined by 2 characters\n");
		stackPushUndefined();
		return;
	}
	for(int i = 0; i < languages_defined; i++)
	{
		if(!strcmp(languages[i], str))
		{
			printf("%s is already an added language\n", str);
			stackPushUndefined();
			return;
		}
	}
	if(languages_defined == MAX_LANGUAGES)
	{
		printf("Cannot add another language. Already got %d languages\n", MAX_LANGUAGES);
		stackPushUndefined();
		return;
	}
	strcpy(languages[languages_defined], str);
	languages_defined++;
	//printf("Added %s as language %d\n", str, languages_defined);
	stackPushInt(0);
}

void add_lang_item(char* lang, char* item, char* txt)
{
	//printf("adding %s to %s, contents: %s\n", item, lang, txt);
	int language_number = -1;
	for(int i = 0; i < languages_defined; i++)
	{
		if(languages[i][0] == lang[0] && languages[i][1] == lang[1])
		{
			language_number = i;
			break;
		}
	}
	if(language_number == -1)
	{
		printf("Language (%s) not added\n", lang);
		return;
	}
	int language_item_number = language_items_defined;
	for(int i = 0; i < language_items_defined; i++)
	{
		if(!strcmp(language_items[i], item))
		{
			language_item_number = i;
			break;
		}
	}
	if(language_item_number == MAX_LANGUAGE_ITEMS)
	{
		printf("Maximum language items reached\n");
		return;
	}
	bool fill_other_langs = false;
	if(language_item_number == language_items_defined)
	{
		//printf("malloccing item\n");
		char *item_m = (char*)malloc(sizeof(char) * (COD2_MAX_STRINGLENGTH + 1));
		if(item_m == NULL)
		{
			printf("Could not malloc\n");
			return;
		}
		fill_other_langs = true;
		strncpy(item_m, item, COD2_MAX_STRINGLENGTH);
		language_items[language_item_number] = item_m;
		language_items_defined++;
		for(int i = 0; i < languages_defined; i++)
			language_reference_mallocd[i][language_item_number] = false;
	}
	char *txt_m;
	if(!language_reference_mallocd[language_number][language_item_number])
	{
		//printf("malloccing text\n");
		txt_m = (char*)malloc(sizeof(char) * (COD2_MAX_STRINGLENGTH + 1));
		if(txt_m == NULL)
		{
			printf("Could not malloc\n");
			return;
		}
		language_reference_mallocd[language_number][language_item_number] = true;
		language_references[language_number][language_item_number] = txt_m;
	}
	{
		//printf("reusing previous malloc\n");
		txt_m = language_references[language_number][language_item_number];
	}
	strncpy(txt_m, txt, COD2_MAX_STRINGLENGTH);
	if(fill_other_langs)
	{
		//printf("filling other items\n");
		for(int i = 0; i < languages_defined; i++)
		{
			if(i == language_number)
				continue;
			language_references[i][language_item_number] = txt_m;
		}
	}
}

void gsc_load_languages()
{
	static bool loaded = false;
	char *str;
	if(!stackGetParamString(0, &str))
	{
		printf("Param 0 needs to be a string for load_languages\n");
		stackPushUndefined();
		return;
	}

	int force_reload;
	if(!stackGetParamInt(1, &force_reload))
		force_reload = 0;
	if(!force_reload && loaded)
	{
		printf("Already loaded languages\n");
		stackPushUndefined();
		return;
	}
	char curitem[COD2_MAX_STRINGLENGTH + 1] = "";
	char buffer[COD2_MAX_STRINGLENGTH + 1];
	bool item_found = false;
	FILE * file;
	file = fopen(str, "r");
	int linenum = 0;
	if(file != NULL)
	{
		while(fgets(buffer, sizeof(buffer), file) != NULL)
		{
			linenum++;
			if(!strncmp(buffer, "REFERENCE", 9))
			{
				//read the rest of buffer, starting from the first non-space character
				int start = -1;
				int end = -1;
				for(int i = 9; i < COD2_MAX_STRINGLENGTH; i++)
				{
					if(buffer[i] == '\0' || buffer[i] == '\r' || buffer[i] == '\n')
					{
						end = i;
						if(end - start > 0)
						{
							//string has a length
							//set it as curitem
							strncpy(curitem, &(buffer[start]), end - start);
							curitem[end - start] = '\0';
							//printf("Read item: %s", curitem);
							item_found = true;
						}
						break;
					}
					else if(start == -1 && buffer[i] != ' ' && buffer[i] != '\t')
						start = i;
					else if(start != -1 && (buffer[i] == ' ' || buffer[i] == '\t'))
					{
						//error, trailing whitespace
						//try to cut it off
						end = i;
						if(end - start > 0)
						{
							//string has a length
							//set it as curitem
							strncpy(curitem, &(buffer[start]), end - start);
							curitem[end - start] = '\0';
							//printf("Read item: %s", curitem);
							item_found = true;
						}
						break;
					}
				}
			}
			else if(!strncmp(buffer, "LANG_", 5))
			{
				//language is the [5] and [6]th element of this string
				//rest of string, starting at the first " is the string, ending at the last "
				bool lang_exist = false;
				for(int i = 0; i < languages_defined; i++)
				{
					if(languages[i][0] == buffer[5] && buffer[5] != '\0' && languages[i][1] == buffer[6] && buffer[6] != '\0')
					{
						lang_exist = true;
						break;
					}
				}
				if(!lang_exist)
				{
					if(buffer[5] != '\0' && buffer[6] != '\0')
						printf("Language not yet added for language: %c%c\n", buffer[5], buffer[6]);
					else
						printf("Line ended too soon on line %d\n", linenum);
				}
				else
				{
					//start scanning buffer, starting from 8
					char lang[2];
					lang[0] = buffer[5];
					lang[1] = buffer[6];
					int start = -1;
					int end = -1;
					bool ignore_next = false;
					for(int i = 8; i < COD2_MAX_STRINGLENGTH; i++)
					{
						if(buffer[i] == '\\' && !ignore_next)
						{
							ignore_next = true;
							continue;
						}
						if(buffer[i] == '\0' || buffer[i] == '\r' || buffer[i] == '\n')
						{
							//string ended prematurely
							printf("Error in line %d\n", linenum);
							break;
						}
						if(buffer[i] == '\"' && !ignore_next)
						{
							if(start == -1)
							{
								if(buffer[i + 1] == '\0')
								{
									printf("Premature line end on line %d", linenum);
									break;
								}
								else
									start = i + 1;
							}
							else
							{
								end = i;
								//add buffer to languages stuff
								if(end - start > 0)
								{
									char curdesc[COD2_MAX_STRINGLENGTH + 1];
									strncpy(curdesc, &(buffer[start]), end - start);
									curdesc[end - start] = '\0';
									add_lang_item(lang, curitem, curdesc);
									//printf("Adding %s as %s for language %c%c\n", curdesc, curitem, buffer[5], buffer[6]);
								}
								break;
							}
						}
						ignore_next = false;
					}
				}
			}
		}
		fclose(file);
	}
	else
	{
		printf("File %s does not exist\n", str);
		return;
	}
}

void gsc_get_language_item()
{
	char *str;
	char *str2;
	if(!stackGetParamString(0, &str))
	{
		printf("Param 0 has to be a string for get_language_item\n");
		stackPushUndefined();
		return;
	}
	if(!stackGetParamString(1, &str2))
	{
		printf("Param 1 has to be a string for get_language_item\n");
		stackPushUndefined();
		return;
	}
	//printf("str: %s, str2: %s\n", str, str2);
	if(str[0] == '\0' || str[1] == '\0')
	{
		printf("Invalid language item requested. Should be like EN\n");
		stackPushUndefined();
		return;
	}
	int language_number = -1;
	for(int i = 0; i < languages_defined; i++)
	{
		if(str[0] == languages[i][0] && str[1] == languages[i][1])
		{
			//found a match
			language_number = i;
			break;
		}
	}
	if(language_number == -1)
	{
		printf("Invalid language selected. Load languages first\n");
		stackPushUndefined();
		return;
	}
	int language_item_number = -1;
	for(int i = 0; i < language_items_defined; i++)
	{
		if(!strcmp(str2, language_items[i]))
		{
			//found match
			language_item_number = i;
			break;
		}
	}
	if(language_item_number == -1)
	{
		printf("Invalid language item selected. Load language items first\n");
		stackPushString(str2);
		return;
	}
	//printf("found: %s\n", language_references[language_number][language_item_number]);
	stackPushString(language_references[language_number][language_item_number]);
}

void gsc_themetext()
{
	char *mask = 0;
	char *text = 0;
	char result[COD2_MAX_STRINGLENGTH];
	int num = 0;
	if (!stackGetParams("ss", &mask, &text))
	{
		printf("scriptengine> WARNING: themetext undefined argument!\n");
		stackPushUndefined();
		return;
	}
	while(*mask != 0)
	{
		switch(*mask)
		{
		case 'c':
			if(*text != 0)
				result[num++] = *(text++);
			mask++;
			break;
		case 'C':
			if(*text != 0)
				result[num++] = toupper(*(text++));
			mask++;
			break;
		case 's':
		{
			while(*text != 0)
				result[num++] = *(text++);
			mask++;
			break;
		}
		default:
			result[num++] = *(mask++);
			break;
		}
	}
	while(*text != 0)
		result[num++] = *(text++);
	result[num] = '\0';
	stackPushString(result);
}

void gsc_utils_sprintf()
{
	char result[COD2_MAX_STRINGLENGTH];
	char *str;
	if (!stackGetParams("s", &str))
	{
		printf("scriptengine> WARNING: sprintf undefined argument!\n");
		stackPushUndefined();
		return;
	}
	int param = 1; // maps to first %
	int len = strlen(str);
	int num = 0;
	for (int i = 0; i < len; i++)
	{
		if (str[i] == '%')
		{
			if(str[i + 1] == '%')
			{
				result[num++] = '%';
				i++;
			}
			else
			{
				if(param >= stackGetNumberOfParams())
					continue;
				switch (stackGetParamType(param))
				{
				case STACK_STRING:
					char *tmp_str;
					stackGetParamString(param, &tmp_str); // no error checking, since we know it's a string
					num += sprintf(&(result[num]), "%s", tmp_str);
					break;
				case STACK_VECTOR:
					float vec[3];
					stackGetParamVector(param, vec);
					num += sprintf(&(result[num]), "(%.2f, %.2f, %.2f)", vec[0], vec[1], vec[2]);
					break;
				case STACK_FLOAT:
					float tmp_float;
					stackGetParamFloat(param, &tmp_float);
					num += sprintf(&(result[num]), "%.3f", tmp_float); // need a way to define precision
					break;
				case STACK_INT:
					int tmp_int;
					stackGetParamInt(param, &tmp_int);
					num += sprintf(&(result[num]), "%d", tmp_int);
					break;
				}
				param++;
			}
		}
		else
			result[num++] = str[i];
	}
	result[num] = '\0';
	stackPushString(result);
}

void gsc_utils_disableGlobalPlayerCollision()
{
	// well, i could also just write LEAVE,RETN C9,C3 at beginnung of function
#  if COD_VERSION == COD2_1_0
	cracking_write_hex(0x080F474A, (char *)"C3");
	cracking_write_hex(0x080F5199, (char *)"02");
	cracking_write_hex(0x0805AA0E, (char *)"C3");
#elif COD_VERSION == COD2_1_2
	////ret = cracking_nop(0x080F6D5A, 0x080F7150);
	//ret = cracking_nop(0x080F6E82, 0x080F7150); // requires setcontents(0) hack and brushmodels arent working
	cracking_write_hex(0x080F6D5A, (char *)"C3");
	cracking_write_hex(0x080F77AD, (char *)"02");
	cracking_write_hex(0x0805AC1A, (char *)"C3");

	cracking_hook_function(0x80F6D5A, (int)utils_hook_player_eject);
	cracking_hook_function(0x80F553E, (int)utils_hook_player_eject); //g_setclientcontents
#if 0
	//just a quick snippet for if u want to switch to turn it on or off
	unsigned char on[5] = {0x90};
	unsigned char off[5] = {0xe8, 0xbd, 0xf5, 0xff, 0xff};
	memcmp((void*)0x80F6D5A, on, 5);
#endif
#elif COD_VERSION == COD2_1_3
	//ret = cracking_nop(0x080F6E9E, 0x080F7294);
	//ret = cracking_nop(0x080F6FC6, 0x080F7294);
	cracking_write_hex(0x080F6E9E, (char *)"C3");
	cracking_write_hex(0x080F78F1, (char *)"02");
	cracking_write_hex(0x0805AC12, (char *)"C3");

	cracking_hook_function(0x80F6E9E, (int)utils_hook_player_eject);
	cracking_hook_function(0x80F5682, (int)utils_hook_player_eject); //g_setclientcontents
#endif
	stackPushUndefined();
}

void gsc_utils_getAscii()
{
	char *str;
	if ( ! stackGetParams("s", &str) || strlen(str) == 0)
	{
		stackPushUndefined();
		return;
	}
	stackPushInt(str[0]);
}

void gsc_utils_toupper()
{
	char *str;
	int offset = 0;
	int len = 0;
	if ( ! stackGetParams("s", &str) || strlen(str) == 0)
	{
		stackPushString("");
		return;
	}

	stackGetParamInt(1, &offset);
	if(offset < 0)
		offset = 0;
	if(!stackGetParamInt(2, &len) || len == 0)
		len = strlen(str);
	if(len - offset > strlen(str))
		len = strlen(str) - offset;
	if(len <= 0)
	{
		stackPushString("");
		return;
	}

	int maxlen = strlen(str);
	char result[maxlen+1];
	strcpy(result, str);

	for (int i = offset; i < len; i++)
	{
		result[i] = toupper(str[i]);
	}
	result[maxlen] = '\0';

	stackPushString(result);
}

void gsc_utils_system()   // closer 903, "ls"
{
	char *cmd;
	if ( ! stackGetParams("s",  &cmd))
	{
		printf("scriptengine> ERROR: please specify the command as string to gsc_system_command()\n");
		stackPushUndefined();
		return;
	}
	setenv("LD_PRELOAD", "", 1); // dont inherit lib of parent
	stackPushInt( system(cmd) );
}

// http://stackoverflow.com/questions/1583234/c-system-function-how-to-collect-the-output-of-the-issued-command
// Calling function must free the returned result.
char* exec(const char* command)
{
	FILE* fp;
	char* line = NULL;
	// Following initialization is equivalent to char* result = ""; and just
	// initializes result to an empty string, only it works with
	// -Werror=write-strings and is so much less clear.
	char* result = (char*) calloc(1, 1);
	size_t len = 0;

	fflush(NULL);
	fp = popen(command, "r");
	if (fp == NULL)
	{
		printf("Cannot execute command:\n%s\n", command);
		free(result);
		return NULL;
	}

	while(getline(&line, &len, fp) != -1)
	{
		// +1 below to allow room for null terminator.
		result = (char*) realloc(result, strlen(result) + strlen(line) + 1);
		// +1 below so we copy the final null terminator.
		strncpy(result + strlen(result), line, strlen(line) + 1);
		free(line);
		line = NULL;
	}

	fflush(fp);
	if (pclose(fp) != 0)
	{
		perror("Cannot close stream.\n");
		free(result);
		return NULL;
	}

	return result;
}

void gsc_utils_execute()   // Returns complete command output as a string
{
	char *cmd;
	if ( ! stackGetParams("s",  &cmd))
	{
		printf("scriptengine> ERROR: please specify the command as string to gsc_execute_command()\n");
		stackPushUndefined();
		return;
	}
	setenv("LD_PRELOAD", "", 1); // dont inherit lib of parent
	char *result = exec(cmd);
	if (result == NULL)
		stackPushUndefined();
	else
	{
		stackPushString(result);
		free(result);
	}
}

void gsc_utils_exponent()
{
	float basis;
	float exponent;
	if ( ! stackGetParams("ff", &basis, &exponent))
	{
		printf("scriptengine> ERROR: please specify the commands as float to gsc_exponent_command()\n");
		stackPushUndefined();
		return;
	}
	stackPushFloat( pow(basis, exponent) );
}

void gsc_utils_file_link()
{
	char *source, *dest;
	if ( ! stackGetParams("ss",  &source, &dest))
	{
		printf("scriptengine> ERROR: please specify source and dest to gsc_link_file()\n");
		stackPushUndefined();
		return;
	}
	stackPushInt( link(source, dest) ); // 0 == success
}

void gsc_utils_file_unlink()
{
	char *file;
	if ( ! stackGetParams("s",  &file))
	{
		printf("scriptengine> ERROR: please specify file to gsc_unlink_file()\n");
		stackPushUndefined();
		return;
	}
	stackPushInt( unlink(file) ); // 0 == success
}

void gsc_utils_file_exists()
{
	char *filename;
	if ( ! stackGetParams("s", &filename))
	{
		stackPushUndefined();
		return;
	}
	stackPushInt( ! (access(filename, F_OK) == -1) );
}

void gsc_utils_FS_LoadDir()
{
	char *path, *dir;
	if ( ! stackGetParams("ss", &path, &dir))
	{
		stackPushUndefined();
		return;
	}
	//printf("path %s dir %s \n", path, dir);
	stackPushInt( FS_LoadDir(path, dir) );
}

void gsc_utils_getType()
{
	if (stackGetNumberOfParams() == 0)
	{
		stackPushUndefined();
		return;
	}
	stackPushString( stackGetParamTypeAsString(0) );
}

void gsc_utils_stringToFloat()
{
	char *str;
	if ( ! stackGetParams("s", &str))
	{
		stackPushUndefined();
		return;
	}
	stackPushFloat( atof(str) );
}

// rundll("print.so", "test_print")
void gsc_utils_rundll()
{
	char *arg_library, *arg_function;
	if ( ! stackGetParams("ss", &arg_library, &arg_function))
	{
		printf("scriptengine> wrongs args for: rundll(library, function)\n");
		stackPushUndefined();
		return;
	}
	printf("lib=%s func=%s\n", arg_library, arg_function);
	//void *handle = dlopen(arg_library, RTLD_GLOBAL); // crashes
	//void *handle = dlopen(arg_library, RTLD_LOCAL); // crashes
	//void *handle = dlopen(arg_library, RTLD_NOW); // crashes
	void *handle = dlopen(arg_library, RTLD_LAZY);
	if ( ! handle)
	{
		printf("ERROR: dlopen(\"%s\") failed!\n", arg_library);
		stackPushInt(0);
		return;
	}
	printf("dlopen(\"%s\") returned: %.8x\n", arg_library, (unsigned int)handle);
	void (*func)();
	//*((void *)&func) = dlsym(handle, arg_function);
	*(int *)&func = (int)dlsym(handle, arg_function);
	if (!func)
	{
		printf("ERROR: dlsym(\"%s\") failed!\n", arg_function);
		stackPushInt(0);
		return;
	}
	printf("function-name=%s -> address=%.8x\n", arg_function, (unsigned int)func);
	func();
	dlclose(handle);
	stackPushInt(1);
}

void gsc_utils_ExecuteString()
{
	char *str;
	if ( ! stackGetParams("s", &str))
	{
		stackPushUndefined();
		return;
	}
	Cmd_ExecuteString(str);
	stackPushInt(1);
}

void gsc_utils_sendgameservercommand()
{
	int clientNum;
	char *message;
	if ( ! stackGetParams("is", &clientNum, &message))
	{
		stackPushUndefined();
		return;
	}
	SV_GameSendServerCommand(clientNum, 0, message);
	stackPushInt(1);
}

void gsc_utils_scandir()
{
	char *dirname;
	if ( ! stackGetParams("s", &dirname))
	{
		stackPushUndefined();
		return;
	}
	DIR *dir;
	struct dirent *dir_ent;
	dir = opendir(dirname);
	if ( ! dir)
	{
		stackPushUndefined();
		return;
	}
	stackPushArray();
	while (dir_ent = readdir(dir))
	{
		stackPushString(dir_ent->d_name);
		stackPushArrayLast();
	}
	closedir(dir);
}

void gsc_utils_fopen()
{
	char *filename, *mode;
	if ( ! stackGetParams("ss", &filename, &mode))
	{
		stackPushUndefined();
		return;
	}
	FILE *file = fopen(filename, mode);
	stackPushInt((int)file);
}

void gsc_utils_fread()
{
	FILE *file;
	if ( ! stackGetParams("i", &file))
	{
		stackPushUndefined();
		return;
	}
	assert(file);
	char buffer[256];
	int ret = fread(buffer, 1, 255, file);
	if ( ! ret)
	{
		stackPushUndefined();
		return;
	}
	buffer[ret] = '\0';
	stackPushString(buffer);
}

void gsc_utils_fwrite()
{
	FILE *file;
	char *buffer;
	if ( ! stackGetParams("is", &file, &buffer))
	{
		stackPushUndefined();
		return;
	}
	assert(file);
	int bytesWritten = fwrite(buffer, 1, strlen(buffer), file);
	stackPushInt(bytesWritten);
}

void gsc_utils_fclose()
{
	FILE *file;
	if ( ! stackGetParams("i", &file))
	{
		stackPushUndefined();
		return;
	}
	assert(file);
	stackPushInt( fclose(file) );
}

// http://code.metager.de/source/xref/RavenSoftware/jediacademy/code/game/g_utils.cpp#36
void gsc_G_FindConfigstringIndexOriginal()
{
	char *name;
	int min, max, create;
	if ( ! stackGetParams("siii", &name, &min, &max, &create))
	{
		stackPushUndefined();
		return;
	}
	signed int (*sig)(char *name, int min, int max, int create, char *errormessage);
#if COD_VERSION == COD2_1_0
	*(int*)&sig = 0x0811AE70;
#elif COD_VERSION == COD2_1_2
	*(int*)&sig = 0x0811D1A4;
#elif COD_VERSION == COD2_1_3
	*(int*)&sig = 0x0811D300;
#endif
	int ret = sig(name, min, max, create, "G_FindConfigstringIndex() from GSC");
	ret += min; // the real array index
	stackPushInt(ret);
}

// simple version, without crash
void gsc_G_FindConfigstringIndex()
{
	char *name;
	int min, max;
	char* (*func)(int i);
	if ( ! stackGetParams("sii", &name, &min, &max))
	{
		stackPushUndefined();
		return;
	}
#if COD_VERSION == COD2_1_0
	*(int*)&func = 0x08091108;
#elif COD_VERSION == COD2_1_2
	*(int*)&func = 0x08092918;
#elif COD_VERSION == COD2_1_3
	*(int*)&func = 0x08092a1c;
#endif
	for (int i = 1; i < max; i++)
	{
		char *curitem = func(min + i);
		if ( ! *curitem)
			break;
		if ( ! strcasecmp(name, curitem))
		{
			stackPushInt(i + min);
			return;
		}
	}
	stackPushInt(0);
	return;
}

void gsc_get_configstring()
{
	int index;
	char* (*func)(int index);
	if ( ! stackGetParams("i", &index))
	{
		stackPushUndefined();
		return;
	}
#if COD_VERSION == COD2_1_0
	*(int*)&func = 0x08091108;
#elif COD_VERSION == COD2_1_2
	*(int*)&func = 0x08092918;
#elif COD_VERSION == COD2_1_3
	*(int*)&func = 0x08092a1c;
#endif
	char *string = func(index);
	if ( ! *string )
		stackPushUndefined();
	else
		stackPushString(string);
}

void gsc_set_configstring()
{
	int index;
	char *string;
	int (*func)(int index, char *string);
	if ( ! stackGetParams("is", &index, &string))
	{
		stackPushUndefined();
		return;
	}
#if COD_VERSION == COD2_1_0
	*(int*)&func = 0x08090E6C;
#elif COD_VERSION == COD2_1_2
	*(int*)&func = 0x0809267C;
#elif COD_VERSION == COD2_1_3
	*(int*)&func = 0x08092780;
#endif
	stackPushInt(func(index, string));
}

void gsc_call_function_raw()
{
	int func_address;
	char *args;
	unsigned char *data;
	if ( ! stackGetParams("isi", &func_address, &args, &data))
	{
		printf("scriptengine> wrongs args for call_function_raw(func_address, args, data);\n");
		stackPushUndefined();
		return;
	}
	int ret = cracking_call_function(func_address, args, data);
	stackPushInt(ret);
}

void gsc_dlopen()
{
	char *arg_library;
	if ( ! stackGetParams("s", &arg_library))
	{
		printf("scriptengine> wrongs args for: dlopen(library)\n");
		stackPushUndefined();
		return;
	}
	int handle = (int)dlopen(arg_library, RTLD_LAZY);
	if ( ! handle)
	{
		printf("ERROR: dlopen(\"%s\") failed! Error: %s\n", arg_library, dlerror());
		stackPushInt(0);
		return;
	}
	stackPushInt(handle);
}

void gsc_dlsym()
{
	int handle;
	char *arg_function;
	if ( ! stackGetParams("is", &handle, &arg_function))
	{
		printf("scriptengine> wrongs args for: dlsym(handle, function)\n");
		stackPushUndefined();
		return;
	}
	int func = (int)dlsym((void *)handle, arg_function);
	if (!func)
	{
		printf("ERROR: dlsym(\"%s\") failed! Error: %s\n", arg_function, dlerror());
		stackPushInt(0);
		return;
	}
	stackPushInt(func);
}

void gsc_dlclose()
{
	int handle;
	char *arg_function;
	if ( ! stackGetParams("i", &handle))
	{
		printf("scriptengine> wrongs args for: dlclose(handle)\n");
		stackPushUndefined();
		return;
	}
	int ret = dlclose((void *)handle);
	if (ret != 0)
	{
		printf("ERROR: dlclose(%d) failed! Error: %s\n", handle, dlerror());
		stackPushInt(0);
		return;
	}
	stackPushInt(ret);
}

#define MAX_WEAPON_IGNORE_SIZE 20
#define MAX_WEAPON_NAME_SIZE 32
char* defaultweapon_mp = NULL;
char ignoredWeapons[MAX_WEAPON_IGNORE_SIZE][MAX_WEAPON_NAME_SIZE];
int ignoredWeaponCount = 0;

void gsc_utils_init()
{
	if(defaultweapon_mp == NULL)
		defaultweapon_mp = (char*)malloc(MAX_WEAPON_NAME_SIZE);
	if(defaultweapon_mp == NULL)
		printf("Failed to malloc defaultweapon_mp\n");

	strcpy(defaultweapon_mp, "defaultweapon_mp");
	defaultweapon_mp[strlen(defaultweapon_mp)] = '\0';
}

void gsc_utils_free()
{
	free(defaultweapon_mp);
}

bool isOnIgnoreList(char* weapon)
{
	if(ignoredWeaponCount == 0)
		return false;

	for(int i=0; i<ignoredWeaponCount; i++)
	{
		if(strcmp(ignoredWeapons[i], weapon) == 0)
			return true;
	}

	return false;
}

int hook_findWeaponIndex(char* weapon)
{
	typedef int (*findIndexWeapon_t)(char* weapon);
#if COD_VERSION == COD2_1_0
	findIndexWeapon_t findIndexWeapon = (findIndexWeapon_t)0x080E949C;
#elif COD_VERSION == COD2_1_2
	findIndexWeapon_t findIndexWeapon = (findIndexWeapon_t)0x080EBA8C;
#elif COD_VERSION == COD2_1_3
	findIndexWeapon_t findIndexWeapon = (findIndexWeapon_t)0x080EBBD0;
#else
#warning findIndexWeapon_t findIndexWeapon = NULL;
	findIndexWeapon_t findIndexWeapon = (findIndexWeapon_t)NULL;
#endif

	if(isOnIgnoreList(weapon))
		return findIndexWeapon(defaultweapon_mp);
	else
		return findIndexWeapon(weapon);
}

void gsc_utils_resetignoredweapons()
{
	ignoredWeaponCount = 0;
}

void gsc_utils_ignoreweapon()
{
	char* weapon;
	if ( ! stackGetParams("s", &weapon))
	{
		printf("scriptengine> wrongs args for: ignoreWeapon(weapon)\n");
		stackPushUndefined();
		return;
	}

	if(strlen(weapon) > MAX_WEAPON_NAME_SIZE - 1)
	{
		printf("scriptengine> weapon name is too long: ignoreWeapon(weapon)\n");
		stackPushUndefined();
		return;
	}

	if(ignoredWeaponCount >= MAX_WEAPON_IGNORE_SIZE)
	{
		printf("scriptengine> Exceeded MAX_WEAPON_IGNORE_SIZE %d\n", MAX_WEAPON_IGNORE_SIZE);
		stackPushUndefined();
		return;
	}

	strcpy(ignoredWeapons[ignoredWeaponCount], weapon);
	ignoredWeapons[ignoredWeaponCount][strlen(weapon)] = '\0';
	ignoredWeaponCount++;
	stackPushInt(1);
}

void gsc_utils_setdefaultweapon()
{
	char* weapon;
	if ( ! stackGetParams("s", &weapon))
	{
		printf("scriptengine> wrongs args for: setdefaultweapon(weapon)\n");
		stackPushUndefined();
		return;
	}

	if(strlen(weapon) > MAX_WEAPON_NAME_SIZE - 1)
	{
		printf("scriptengine> weapon name is too long: setdefaultweapon(weapon)\n");
		stackPushUndefined();
		return;
	}

	if(strcmp(defaultweapon_mp, weapon) == 0)
	{
		stackPushInt(2);
		return;
	}

	strcpy(defaultweapon_mp, weapon);
	defaultweapon_mp[strlen(weapon)] = '\0';
#if COD_VERSION == COD2_1_0
	memcpy((void*)0x0811E929, &defaultweapon_mp, 4); // default
	memcpy((void*)0x080E8AAD, &defaultweapon_mp, 4); // not found
	//memcpy((void*)0x080F014D, &defaultweapon_mp, 4); // not found backup
	memcpy((void*)0x080E928A, &defaultweapon_mp, 4); // unknown
#elif COD_VERSION == COD2_1_2
	memcpy((void*)0x08120C5A, &defaultweapon_mp, 4); // default
	memcpy((void*)0x080EB09D, &defaultweapon_mp, 4); // not found
	//memcpy((void*)0x080F273D, &defaultweapon_mp, 4); // not found backup
	memcpy((void*)0x080EB87A, &defaultweapon_mp, 4); // unknown
#elif COD_VERSION == COD2_1_3
	memcpy((void*)0x08120DB9, &defaultweapon_mp, 4); // default
	memcpy((void*)0x080EB1E1, &defaultweapon_mp, 4); // not found
	//memcpy((void*)0x080F2881, &defaultweapon_mp, 4); // not found backup
	memcpy((void*)0x080EB9BE, &defaultweapon_mp, 4); // unknown
#endif
	stackPushInt(1);
}

int weaponCount()
{
#if COD_VERSION == COD2_1_0
	return *(int*)0x08576140;
#elif COD_VERSION == COD2_1_2
	return *(int*)0x0858A000;
#elif COD_VERSION == COD2_1_3
	return *(int*)0x08627080; // see 80EBFFE (cod2 1.3)
#else
	return 0;
#endif
}

int getWeapon(int index)
{
	typedef int (*get_weapon_t)(int index);
#if COD_VERSION == COD2_1_0
	get_weapon_t get_weapon = (get_weapon_t)0x080E9270;
#elif COD_VERSION == COD2_1_2
	get_weapon_t get_weapon = (get_weapon_t)0x080EB860;
#elif COD_VERSION == COD2_1_3
	get_weapon_t get_weapon = (get_weapon_t)0x080EB9A4;
#else
#warning get_weapon_t get_weapon = NULL;
	get_weapon_t get_weapon = (get_weapon_t)NULL;
#endif
	return get_weapon(index);
}

bool isValidWeaponId(int id)
{
	int weps = weaponCount();
	if(id >= weps || id < 0 || weps == 0)
		return false;

	return true;
}

void gsc_utils_getweaponoffsetint(char* funcname, int offset)
{
	int id;
	if ( ! stackGetParams("i", &id))
	{
		printf("scriptengine> wrongs args for: %s(id)\n", funcname);
		stackPushInt(0);
		return;
	}

	if(!isValidWeaponId(id))
	{
		printf("scriptengine> index out of bounds: %s(id)\n", funcname);
		stackPushInt(0);
		return;
	}

	int value = *(int*)(getWeapon(id) + offset);
	stackPushInt(value);
}

void gsc_utils_setweaponoffsetint(char* funcname, int offset)
{
	int id;
	int value;
	if ( ! stackGetParams("ii", &id, &value))
	{
		printf("scriptengine> wrongs args for: %s(id, value)\n", funcname);
		stackPushInt(0);
		return;
	}

	if(!isValidWeaponId(id))
	{
		printf("scriptengine> index out of bounds: %s(id, value)\n", funcname);
		stackPushInt(0);
		return;
	}

	int* index = (int*)(getWeapon(id) + offset);
	*index = value;
	stackPushInt(1);
}

void gsc_utils_getweaponmaxammo()
{
	gsc_utils_getweaponoffsetint("getweaponmaxammo", 468);
}

void gsc_utils_getweapondamage()
{
	gsc_utils_getweaponoffsetint("getweapondamage", 492);
}

void gsc_utils_setweapondamage()
{
	gsc_utils_setweaponoffsetint("setweapondamage", 492);
}

void gsc_utils_getweaponmeleedamage()
{
	gsc_utils_getweaponoffsetint("getweapondamage", 500);
}

void gsc_utils_setweaponmeleedamage()
{
	gsc_utils_setweaponoffsetint("setweapondamagemelee", 500);
}

void gsc_utils_getweaponfiretime()
{
	gsc_utils_getweaponoffsetint("getweaponfiretime", 516);
}

void gsc_utils_setweaponfiretime()
{
	gsc_utils_setweaponoffsetint("setweaponfiretime", 516); // see 80EF58A
}

void gsc_utils_getweaponmeleetime()
{
	gsc_utils_getweaponoffsetint("getweaponmeleetime", 532);
}

void gsc_utils_setweaponmeleetime()
{
	gsc_utils_setweaponoffsetint("setweaponmeleetime", 532);
}

void gsc_utils_getweaponreloadtime()
{
	gsc_utils_getweaponoffsetint("getweaponreloadtime", 536);
}

void gsc_utils_setweaponreloadtime()
{
	gsc_utils_setweaponoffsetint("setweaponreloadtime", 536);
}

void gsc_utils_getweaponreloademptytime()
{
	gsc_utils_getweaponoffsetint("getweaponreloademptytime", 540);
}

void gsc_utils_setweaponreloademptytime()
{
	gsc_utils_setweaponoffsetint("setweaponreloademptytime", 540);
}

char* hitlocs[] = {"none", "helmet", "head", "neck", "torso_upper", "torso_lower", "right_arm_upper",
                   "right_arm_lower", "right_hand", "left_arm_upper", "left_arm_lower", "left_hand", "right_leg_upper",
                   "right_leg_lower", "right_foot", "left_leg_upper", "left_leg_lower", "left_foot", "gun"
                  };

int getHitLocOffset(char* hitloc)
{
	int offset = 0; // none
	for (int i=0; i<19; i++) // prevent out of bound
	{
		if(strcmp(hitlocs[i], hitloc) == 0)
		{
			offset = i;
			break;
		}
	}
	return offset;
}

void gsc_utils_getweaponhitlocmultiplier()
{
	int id;
	char* hitloc;
	if ( ! stackGetParams("is", &id, &hitloc))
	{
		printf("scriptengine> wrongs args for: getweaponhitlocmultiplier(id, hitloc)\n");
		stackPushInt(0);
		return;
	}

	if(!isValidWeaponId(id))
	{
		printf("scriptengine> index out of bounds: getweaponhitlocmultiplier(id, hitloc)\n");
		stackPushInt(0);
		return;
	}

	int offset = getHitLocOffset(hitloc);
	float multiplier = *(float*)(getWeapon(id) + 4 * offset + 1456);
	stackPushFloat(multiplier);
}

void gsc_utils_setweaponhitlocmultiplier()
{
	int id;
	float multiplier;
	char* hitloc;
	if ( ! stackGetParams("isf", &id, &hitloc, &multiplier))
	{
		printf("scriptengine> wrongs args for: getweaponhitlocmultiplier(id, hitloc, multiplier)\n");
		stackPushInt(0);
		return;
	}

	if(!isValidWeaponId(id))
	{
		printf("scriptengine> index out of bounds: getweaponhitlocmultiplier(id, hitloc, multiplier)\n");
		stackPushInt(0);
		return;
	}

	int offset = getHitLocOffset(hitloc);
	float* multiPointer = (float*)(getWeapon(id) + 4 * offset + 1456);
	*multiPointer = multiplier;
	stackPushFloat(1);
}

void gsc_utils_getloadedweapons()
{
	stackPushArray();
	int weps = weaponCount();
	if(weps == 0)
		return;

	for(int i=0; i<weps; i++)
	{
		int w = getWeapon(i);
		stackPushString(*(char**)w);
		stackPushArrayLast();
	}

	// the offset are written in hex after each name (e.g fireTime at 8187084 with 0x204 (516))
	// 0 = weapon_mp
	// 4 = display name
	// 468 = max ammo
	// 472 = start ammo
	// 476 = shot count
	// 492 = damage
	// 500 = melee damage
	// 612 = moveSpeedScale // see 80E1C58 (cod2 1.3) call 80E268A
	// 1456 - 1528 = locNone till locGun
	// [id][weapon_mp][worldmodel][viewmodel]: displayname
	//printf("[%d][%s][%s][%s]: %s\n", i, *(char**)w, *(const char **)(w + 436), *(char**)(w + 12), *(char**)(w + 4));
}

void gsc_utils_time() {
	stackPushInt(std::time(NULL));
}

void gsc_utils_strftime() {
	time_t unixtime;
	struct tm *timeinfo;
	char *format = "%Y-%m-%d %H:%M:%S";
	char buffer[COD2_MAX_STRINGLENGTH];

	stackGetParamString(0, &format);

	if (!stackGetParamInt(1, (int*)&unixtime)) {
		time(&unixtime);
	}

	timeinfo = localtime(&unixtime);

	if (strftime(buffer, COD2_MAX_STRINGLENGTH, format, timeinfo)) {
		stackPushString(buffer);
	}
	else {
		printf("scriptengine> strftime failed\n");
		stackPushUndefined();
	}
}

void gsc_utils_strptime() {
	struct tm timeinfo;
	memset(&timeinfo, 0, sizeof(struct tm));
	char *strtime;
	char *format = "%Y-%m-%d %H:%M:%S";

	if (!stackGetParamString(0, &strtime)) {
		printf("scriptengine> wrongs args for: strtotime(strtime[, format = \"%%Y-%%m-%%d %%H:%%M:%%S\"])\n");
		stackPushUndefined();
		return;
	}

	stackGetParamString(1, &format);

	if (strptime(strtime, format, &timeinfo)) {
		stackPushInt(mktime(&timeinfo)); // returning unixtime for now
		
		// TODO: figure out how to push struct/array with string keys
		/*
		stackPushArray();
		
		stackPushString("tm_sec");
		stackPushInt(timeinfo.tm_sec);
		stackPushArrayLast();
		
		stackPushString("tm_min");
		stackPushInt(timeinfo.tm_min);
		stackPushArrayLast();
		
		stackPushString("tm_hour");
		stackPushInt(timeinfo.tm_hour);
		stackPushArrayLast();
		
		stackPushString("tm_mday");
		stackPushInt(timeinfo.tm_mday);
		stackPushArrayLast();

		stackPushString("tm_mon");
		stackPushInt(timeinfo.tm_mon);
		stackPushArrayLast();
		
		stackPushString("tm_year");
		stackPushInt(timeinfo.tm_year);
		stackPushArrayLast();

		stackPushString("tm_wday");
		stackPushInt(timeinfo.tm_wday);
		stackPushArrayLast();

		stackPushString("tm_yday");
		stackPushInt(timeinfo.tm_yday);
		stackPushArrayLast();

		stackPushString("tm_isdst");
		stackPushInt(timeinfo.tm_isdst);
		stackPushArrayLast();
		*/
	}
	else {
		printf("scriptengine> strptime failed\n");
		stackPushUndefined();
	}
}

void gsc_utils_strreplace() {
	const char* cc_source;
	const char* cc_find;
	const char* cc_replace;

	if (!stackGetParams("sss", &cc_source, &cc_find, &cc_replace)) {
		printf("scriptengine> wrongs args for: strreplace(source, find, replace)\n");
		stackPushUndefined();
		return;
	}

	std::string source(cc_source);
	const std::string find(cc_find);
	const std::string replace(cc_replace);
    for (std::string::size_type i = 0; (i = source.find(find, i)) != std::string::npos;) {
        source.replace(i, find.length(), replace);
        i += replace.length();
    }

	stackPushString((char*) source.c_str());
}

void gsc_utils_strseconds() {
	unsigned int days, hours, minutes, seconds;
	char buffer[COD2_MAX_STRINGLENGTH];

	if (!stackGetParams("i", &seconds)) {
		printf("scriptengine> wrong args for: strseconds(seconds)\n");
	}

	seconds /= 60;
	minutes = seconds % 60;
	seconds /= 60;
	hours = seconds % 24;
	days = seconds / 24;

	int length = 0;
	if (days)    length += sprintf(buffer + length, "%d day%s, "   , days,    (days    != 1 ? "s" : ""));
	if (hours)   length += sprintf(buffer + length, "%d hour%s, "  , hours,   (hours   != 1 ? "s" : ""));
	if (minutes) length += sprintf(buffer + length, "%d minute%s, ", minutes, (minutes != 1 ? "s" : ""));
	if (seconds || !length)
		length += sprintf(buffer + length, "%d second%s, ", seconds, (seconds != 1 ? "s" : ""));

	buffer[length - 1] = 0;
	buffer[length - 2] = 0;

	stackPushString(buffer);
}

void utils_stripcolorcodes(char *str) {
	char *src = str, *dst = src;
	
	while (*src)
		if (*src == '^' && isdigit(*(src + 1)))
			src += 2;
		else
			*dst++ = *src++;
	
	*dst = '\0';
}

void gsc_utils_stripcolors() {
	const char *str;

	if (!stackGetParams("s", &str)) {
		printf("scriptengine> wrong args for: stripcolors(str)\n");
	}

	char *result = (char*)malloc(strlen(str));
	strcpy(result, str);
	utils_stripcolorcodes(result);
	stackPushString(result);
}

#endif
