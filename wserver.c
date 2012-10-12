/* A simple HTTPS server */
#include "common.h"
#include "server.h"

static int http_serve(SSL *ssl, int s)
{
	char buf[BUFSIZZ];
	int r,len;
	BIO *io,*ssl_bio;

	io=BIO_new(BIO_f_buffer());
	ssl_bio=BIO_new(BIO_f_ssl());
	BIO_set_ssl(ssl_bio,ssl,BIO_CLOSE);
	BIO_push(io,ssl_bio);

	while(1){
		r=BIO_gets(io,buf,BUFSIZZ-1);

		switch(SSL_get_error(ssl,r)){
		case SSL_ERROR_NONE:
			len=r;
			break;
		default:
			berr_exit("SSL read problem");
		}

		/* Look for the blank line that signals
		   the end of the HTTP headers */
		if(!strcmp(buf,"\r\n") ||
			!strcmp(buf,"\n"))
			break;
	}

	if((r=BIO_puts
			(io,"HTTP/1.0 200 OK\r\n"))<=0)
		err_exit("Write error");
	if((r=BIO_puts(io,"Content-type: text/plain\r\n"))<=0)
		err_exit("Write error");
	if((r=BIO_puts(io,"Server: EKRServer\r\n"))<=0)
		err_exit("Write error");
	// end of headers
	if((r=BIO_puts(io,"\r\n"))<=0)
		err_exit("Write error");

	char buff[1024];

	SSL_SESSION* session = SSL_get_session(ssl);

	snprintf(buff, sizeof(buff), "Version: 0x%x\n", SSL_version(ssl));
	if((r=BIO_puts(io,buff))<=0)
		err_exit("Write error");

	STACK_OF(SSL_CIPHER) *ciphers = session->ciphers;
	SSL_CIPHER *c;
	int n = sk_SSL_CIPHER_num(ciphers);
	snprintf(buff,sizeof(buff), "client sent %d ciphers\n", n);
	if((r=BIO_puts(io,buff))<=0)
		err_exit("Write error");

	int i;
	for (i = 0; i < n; i++)
	{
		c = sk_SSL_CIPHER_value(ciphers, i);
		snprintf(buff, sizeof(buff), "client [%2d of %2d]: %s\n", i, n, SSL_CIPHER_get_name(c));
		if((r=BIO_puts(io,buff))<=0)
			err_exit("Write error");

	}

	if((r=BIO_flush(io))<0)
		err_exit("Error flushing BIO");



	r=SSL_shutdown(ssl);
	if(!r){
		/* If we called SSL_shutdown() first then
		   we always get return value of '0'. In
		   this case, try again, but first send a
		   TCP FIN to trigger the other side's
		   close_notify*/
		shutdown(s,1);
		r=SSL_shutdown(ssl);
	}

	switch(r){  
	case 1:
		break; /* Success */
	case 0:
	case -1:
	default:
		berr_exit("Shutdown failed");
	}

	SSL_free(ssl);
	close(s);

	return(0);
}


void server(int protocol)
{
	int sock,s;
	BIO *sbio;
	SSL_CTX *ctx;
	SSL *ssl;
	int r;
	pid_t pid;

	/* Build our SSL context*/
	ctx=initialize_ctx(KEYFILE,PASSWORD);
	load_dh_params(ctx,DHFILE);
	SSL_CTX_set_cipher_list(ctx,"ALL");
	long options = SSL_OP_NO_TICKET | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
	int port;
	switch (protocol)
	{
	case SSL2_VERSION:
		options |= SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
		port = 4434;
		break;
	case SSL3_VERSION:
		options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
		port = 4435;
		break;
	case TLS1_VERSION:
		options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
		port = 4436;
		break;
	case TLS1_1_VERSION:
		options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_2;
		port = 4437;
		break;
	case TLS1_2_VERSION:
		options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
		port = 4438;
		break;
	default:
		err_exit("Unexpected protocol value");
	}
	SSL_CTX_set_options(ctx, options);

	sock=tcp_listen(port);

	while(1){
		if((s=accept(sock,0,0))<0)
			err_exit("Problem accepting");

		if((pid=fork())){
			close(s);
		}
		else {
			sbio=BIO_new_socket(s,BIO_NOCLOSE);
			ssl=SSL_new(ctx);
			SSL_set_bio(ssl,sbio,sbio);

			if((r=SSL_accept(ssl)<=0))
				berr_exit("SSL accept error");

			http_serve(ssl,s);
			exit(0);
		}
	}
	destroy_ctx(ctx);
}

int main(int argc, char **argv)
{
	server(TLS1_VERSION);
	exit(0);
}
