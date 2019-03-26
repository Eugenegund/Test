#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include "jsmn.h"
#include <stdlib.h>
#include <syslog.h>

// Разбор запроса от прокси-сервера
int
ParsingRequest(
char*	request, 	// Запрос
char* 	channel_Id,	// Tег канала запроса
char*	protocol,	// Протокол передачи 
char* 	url,		// Указатель ресурса
int	lenUrl);	// Длина указателя ресурса

// В буфер newUrl записывает новый указатель ресурса с учетом перенаправления
int
ToChangeUrl(
char*	channel_Id,	// Tег канала запроса
char*	url,		// Пред. указатель ресурса
char* 	newUrl);	// Новый указатель ресурса
		
// Проверка - равен ли ключ строке
int
CheckKeyJson(
const char*	json,	// Строка формата JSON
jsmntok_t*	tok, 	// Указатель на узел JSON
const char*	s);	// Искомый ключ

int main()
{
	// Устанавливаем связь с программой, ведущей системный журнал
	openlog("squid-redirect", LOG_PID, LOG_USER);

	char* AnswerCodeOk = "OK rewrite-url=";
	char* AnswerCodeERR = "ERR";
	char Request[256];	
	int CountByteRead = read(1, Request, 256);
	Request[CountByteRead] = 0;
	
	char Channel_Id[10]; 
	char Protocol[10]; 
	char Url[50]; 
	char NewUrl[50];
	int ResultCodeParsingRequest = -1;
	ResultCodeParsingRequest = ParsingRequest(Request, Channel_Id, Protocol, Url, strlen(Request));

	int ResultCodeChangeUrl = -1;
	ResultCodeChangeUrl = ToChangeUrl(Channel_Id, Url, NewUrl);

	char Answer[256];
	if(-1 == ResultCodeChangeUrl || -1 == ResultCodeParsingRequest)
	{
		sprintf(Answer, "%s %s %s", Channel_Id, AnswerCodeERR, "\n");
	}
	else
	{
		sprintf(Answer, "%s %s%s%s %s", Channel_Id, AnswerCodeOk, Protocol, NewUrl, "\n");
	}

	// Отправляем буфер с ответом прокси-серверу
	write(1, Answer, strlen(Answer));	
	
	closelog();
	return 0;
}
 
 
 
int ParsingRequest(char* request, char* channel_Id, char* protocol, char* url, int lenUrl)
{
	syslog(LOG_INFO, "Start parsing the request: %s ", request);	
	
	int IndexEndId = -1;
	int IndexEndUrl = -1;
	int IndexEndProtocol = -1;
	for(int i = 0; i < lenUrl; i++)
	{
		if(' ' == *(request + i))
		{	
			IndexEndId = (-1 == IndexEndUrl) ? i : IndexEndId;
		}
		if('/' == *(request + i) && '/' == *(request + i - 1))
		{
			IndexEndProtocol = i;
		}
		if('/' == *(request + i) && '/' != *(request + i - 1))
		{
			IndexEndUrl = i;
		}
	
	}

	if(0 > IndexEndId + IndexEndUrl + IndexEndProtocol)
	{
		syslog(LOG_ERR, "Unable to parse request");			
		return -1;
	}

	snprintf(channel_Id, IndexEndId + 1, request);
	snprintf(protocol, IndexEndProtocol - IndexEndId + 1, request + (IndexEndId + 1));
	snprintf(url, IndexEndUrl - IndexEndProtocol, request + (IndexEndProtocol + 1));

	return 0;
}


int ToChangeUrl(char* channel_Id, char* url, char* newUrl)	
{
	syslog(LOG_INFO, "Finding the address to redirect to: %s ", url);	

	/*char* JsonString =
	"{\"wikipedia.org\": \"lurkmore.to\", \"yandex.ru\": \"kernel.org\", \"ya.ru\": \"mail.ru\"}";*/
	
	int RedirectBase = -1;
	RedirectBase = open("/etc/squid/RedirectBase.json", O_RDONLY);
	if(0 > RedirectBase)
	{
		close(RedirectBase);
		syslog(LOG_ERR, "Redirection base not found");			
		return -1;
	}


	/**/
	char* TextBuf = NULL; 
	struct stat statistics;
        if (stat("/etc/squid/RedirectBase.json", &statistics) != -1)
	{
                TextBuf = (char*)malloc(statistics.st_size);
	}
	else
	{
		close(RedirectBase);
		syslog(LOG_ERR, "Failed to allocate memory");			
		return -1;
	}

	long int CountBytesRead = 0;
	long int SummCountByte = 0;
	while ((CountBytesRead = read (RedirectBase, TextBuf, statistics.st_size)) > 0)
	{
		if(-1 == CountBytesRead)
		{
			close(RedirectBase);
			syslog(LOG_ERR, "Could not read redirection base");
			free(TextBuf);			
			return -1;
		}
		SummCountByte += CountBytesRead;

	}
	TextBuf[SummCountByte] = 0;
	
		
	jsmn_parser JsonParser;
	// Инициализацмя парсера
	jsmn_init(&JsonParser);
	// Все узлы (Учитываем не более 200-T)
	jsmntok_t Toks[200];

	int CountTok;
	CountTok = jsmn_parse(&JsonParser, TextBuf, strlen(TextBuf), Toks, sizeof(Toks)/sizeof(Toks[0]));
	if (CountTok < 0) {
		close(RedirectBase);
		syslog(LOG_ERR, "Error parsing JSON: No objects found");
		free(TextBuf);				
		return -1;
	}

	// Элемент "верхнего уровня" в json файле - "объект"
	if (CountTok < 1 || Toks[0].type != JSMN_OBJECT) {
		close(RedirectBase);
		syslog(LOG_ERR, "Error parsing JSON: Invalid top-level object");
		free(TextBuf);				
		return -1;
	}
	// Пробегаем по всем ключам
	for (int i = 1; i < CountTok; i++) {
		if (CheckKeyJson(TextBuf, &Toks[i], url) == 0)
		{
			snprintf(newUrl, Toks[i+1].end-Toks[i+1].start + 1, TextBuf + Toks[i+1].start);			
			i++;
		} 
	}

	close(RedirectBase);
	free(TextBuf);	
	syslog(LOG_INFO, "Address replacement: %s ", newUrl);
	return 0;
}	

int CheckKeyJson(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}
