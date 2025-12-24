#!/bin/bash
# install.sh - Install ZipRaider-C

echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y libzip-dev libssl-dev gcc make

echo "Compiling ZipRaider-C..."
make

echo "Installing..."
sudo make install

echo "Installation complete!"
echo "Usage: zipraider -f encrypted.zip -w rockyou.txt"
