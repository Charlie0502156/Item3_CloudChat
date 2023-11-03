# Item3_CloudChat

My project is a networked cloud server connecting clients to ajust the outflow of a dam

its done by a clients computer connects to a cloud server and can send commands which then gets encrypted and sent to the dam which proccesses the command and sends a conformation back still encrypted and then to the client again

But if a computer could be connected to the dams network just being able to read the packets being sent through even though they are encrypted they can be analised and abused due to no other security

Using wireshark it can be very easy to filter and read the commands being sent to the dam, then using some scripts it would be possible to capture the packets and replace them

I added another server to demonstrate when it would look like, the messages all pass through it and it can print the out but doesn't know what they mean because they are encrypted and it similarly gets the encrypted output from the dam, after recorded enough of them it could recive an ecrypted message which I knows what the output would be so it could replace it with another that it knows and then send a different confirmation as well so the client can't know whats happening  

Source
ChatGPT for learning how to use threading

There is a diagram on Domputer.drawio.png
