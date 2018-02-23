#include <uv.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <memory.h>


uv_tcp_t   _server;
uv_tcp_t   _client;

int igropyr_start(int port);
static void igropyr_on_connection(uv_stream_t* server, int status);


int igropyr_start(int port) {
	struct sockaddr_in addr;
	uv_ip4_addr("0.0.0.0", port, &addr);
	uv_tcp_init(uv_default_loop(), &_server);
	uv_tcp_bind(&_server, (const struct sockaddr*) &addr, 0);
	uv_listen((uv_stream_t*)&_server, 8, igropyr_on_connection);

	return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

static void after_uv_close(uv_handle_t* handle) {
	free(handle); 
}

static void after_uv_write(uv_write_t* w, int status) {
	if(w->data)
		free(w->data);
	uv_close((uv_handle_t*)w->handle, after_uv_close); 
	free(w);
}

static void write_uv_data(uv_stream_t* stream, const void* data, unsigned int len, int need_copy_data) {
	uv_buf_t buf;
	uv_write_t* w;
	void* newdata  = (void*)data;

	if(data == NULL || len == 0) return;
	if(len ==(unsigned int)-1)
		len = strlen(data);

	if(need_copy_data) {
		newdata = malloc(len);
		memcpy(newdata, data, len);
	}

	buf = uv_buf_init(newdata, len);
	w = (uv_write_t*)malloc(sizeof(uv_write_t));
	w->data = need_copy_data ? newdata : NULL;
	uv_write(w, stream, &buf, 1, after_uv_write); 
}

static const char* http_respone = "HTTP/1.1 200 OK\r\n"
	"Content-Type:text/html;charset=utf-8\r\n"
	"Content-Length:18\r\n"
	"\r\n"
	"Welcome to Igropyr";

static void igropyr_on_connection(uv_stream_t* server, int status) {
	assert(server == (uv_stream_t*)&_server);
	if(status == 0) {
		uv_tcp_t* client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		uv_tcp_init(uv_default_loop(), client);
		uv_accept((uv_stream_t*)&_server, (uv_stream_t*)client);
		write_uv_data((uv_stream_t*)client, http_respone, -1, 0);
	}
}
