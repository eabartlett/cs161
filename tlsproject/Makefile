all:
	gcc -w -I ~/gmp_build_dir/ aes.c sha256.c client.c -o client -L ~/gmp_build_dir/.libs/ -lgmp
clean:
	rm client
measandwich:
	gcc -w aes.c sha256.c client.c -o client -lgmp
