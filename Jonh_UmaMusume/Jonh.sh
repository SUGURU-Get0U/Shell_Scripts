#!/bin/bash -x

echo "Uchirawa uwasano umamusume!"
echo "Generating Keys..."
openssl genrsa -out jonhUmamusume_key.pem 2048 # does something really cool
openssl rsa -in jonhUmamusume_key.pem -pubout -out jonhUmamusume_public.pem # creates some shi

echo "john umamusume signs the private key"
echo "john's message" > blackmail-CreditCardCloneApp.txt
openssl dgst -sha1 -sign jonhUmamusume_key.pem -out jonhUmamusume.sign blackmail-CreditCardCloneApp.txt

# things have run out of control!
# lady miyabi please step on me

# tried running ./jonh.sh failed miserably
# apperantly i have no permition

# ls -l jonh.sh show some shi
# i have no permitions at all <3
# chmod +x jonh.sh

# or u could run
# BASH jonh.sh
# then you dont need permitions, first way is cooler and you can show off!