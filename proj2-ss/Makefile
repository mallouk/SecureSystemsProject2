

all:
	echo "Do Nothing"

ca:
	@./conf_ca

server:
	@./conf_server

clean:
	rm -rf ca
	rm -rf server
	rm -rf clients

verify:
	@echo "Verify CA Cert..."
	openssl x509 -in ./ca/securesysCA.crt
	@echo ""
	@echo ""
	@echo "Verify Server Cert..."
	openssl x509 -in ./server/securesysServer.crt

