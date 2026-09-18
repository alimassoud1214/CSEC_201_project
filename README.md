# CSEC 201 - Remote File Management Protocol (RFMP)

## Group Members
- Ali Massoud
- Team Member 2
- Team Member 3

## Project Files
- crypto_util.py: Caesar cipher and RSA key encryption helper routines
- alimassoud_server.py: Multithreaded Python server handling RFMP setup, operations, and closing phases
- alimassoud_client.py: Interactive Python client supporting encrypted and non-encrypted communications
- alimassoud_client.c: Non-secured C client implementing the openRead command
- Sockets Project with AI.docx: Project instruction sheet, full code listings, and GenAI logs

## How to Run the Programs

To start the multithreaded Python server, run this in your terminal:
python3 alimassoud_server.py

To run the interactive Python client, open a second terminal window and run:
python3 alimassoud_client.py

To compile and execute the C client, run these commands in your terminal:
gcc alimassoud_client.c -o c_client
./c_client