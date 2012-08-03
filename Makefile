all: clean
	erlc src/*.erl
	erlc dep/*.erl
	cp shebang tcpserver
	zip -1 beam.zip *beam
	cat beam.zip >> tcpserver
	rm beam.zip *beam
	chmod 755 tcpserver

.PHONY: clean

clean:
	rm *beam 2>/dev/null || true
	rm tcpserver 2>/dev/null || true
