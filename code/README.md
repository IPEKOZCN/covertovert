Covert Storage Channel that exploits Protocol Field Manipulation using Leap Indicator field in NTP [Code: CSC-PSV-NTP-LI]

We created a secret storage channel for our assignment by tinkering with the Network Time Protocol's (NTP) Leap Indicator (LI) field. Our objective was to develop a covert method of network message transmission that would be difficult to identify. We will describe what we did, how it operates, and some of the difficulties we had in this report.


Covert Channel

A covert channel is comparable to a data conduit that is kept secret. It makes it possible to send data in methods that get beyond standard security measures.   Knowing these pathways aids in cybersecurity through avoiding undesired data breaches. Two primary categories of covert channels exist. The first is called a Covert Timing Channel, which modifies the timing of events, like the intervals between packet transmissions, to conceal data. The second type is called Covert Storage Channels, which insert data into valid sections of protocols or packets of information, like headers' unused fields.
We chose to work on a covert storage channel because it involves hiding data within existing protocol fields, making it harder to detect without disrupting normal network operations. Also, NTP is used to synchronize clocks across devices on a network. It has a small field called the Leap Indicator (LI), which is only 2 bits. This field signals if there’s going to be a leap second adjustment (like adding an extra second to the clock), but it’s not used very often. This made it a perfect candidate for our hidden communication channel.


Implementation


Encoding and Decoding with Bit Manipulation


We used a specific bit manipulation technique to hide our messages within the LI field. Here's a detailed explanation of our process:

Message Encoding

First, we took the message we wanted to send, denoted as M. To disguise our data and make it blend seamlessly with normal traffic, we prefixed each character in M with a fake "1" bit. This transformed each character from an 8-bit sequence to a 9-bit sequence.
Next, we divided each 9-bit sequence into three separate 3-bit groups. This grouping helped us manage the data more effectively for encoding. For each of these 3-bit groups, we performed a division by 3, obtaining both the quotient and the remainder. Since both the quotient and the remainder can be represented using 2 bits each, we encoded each 3-bit group into a 4-bit sequence (2 bits for the quotient and 2 bits for the remainder). This approach maintained a good data ratio, allowing efficient encoding of our message.
After encoding all the groups, we organized the resulting bits into a final bitstream ready for transmission.

Embedding in the LI Field

Once we had our encoded bitstream, we proceeded to embed it into the LI field of NTP packets. Each 4-bit encoded group was split into two separate 2-bit parts. The first 2 bits were used to set the LI field of one NTP packet, and the second 2 bits were used to set the LI field of the next packet.
Importantly, we avoided using the 11 value for the LI field during data transmission to ensure that our packets remained valid and did not trigger any system warnings. The 11 value was exclusively reserved to indicate the end of our message, represented by a dot (.). By adhering to this strategy, we maintained the stealthiness of our covert channel while ensuring protocol compliance.

Decoding the Message

On the receiving end, the process was reversed to decode the hidden message:
    1. Packet Sniffing: The receiver monitored NTP traffic and extracted the LI field from the relevant packets.
    2. Reconstructing Encoded Data: The receiver collected the 4-bit groups from the LI fields of the intercepted packets.
    3. Reverse Encoding: Each 4-bit group was converted back into the original 3-bit groups by reversing the division and remainder process.
    4. Removing the Fake Bit: After reconstructing the 3-bit groups, the fake "1" bit added at the beginning of each character was stripped off, reverting the data back to the original 8-bit characters.
    5. Reconstructing the Message: Finally, the receiver combined these characters to retrieve the original message M.
By following these steps, the receiver could accurately decode the hidden message without any knowledge of the specific encoding scheme used, ensuring that the covert communication remained undetected.
Detailed Implementation
1. Message Encoding
We began with the actual message M that we wanted to send. To obscure our data within normal traffic patterns, we prefixed each character in M with a fake "1" bit, transforming each character into a 9-bit sequence. These 9-bit sequences were then divided into three separate 3-bit groups each. For each 3-bit group, we calculated the quotient and remainder when divided by 3, resulting in two 2-bit values. This encoding method allowed us to convert each 3-bit group into a 4-bit sequence, maintaining an efficient data ratio. The encoded bits were then organized into a final bitstream ready for transmission.
2. Embedding in LI Field
Each 4-bit encoded group was split into two 2-bit parts. The first 2 bits were used to set the LI field of one NTP packet, while the second 2 bits were used for the LI field of the next packet. By exclusively using the 00, 01, and 10 values for the LI field during data transmission, we ensured that our packets remained valid and did not trigger any system warnings. After the entire message was transmitted, we set the LI field to 11 to indicate the end of the message, represented by a dot (.).
3. Decoding Process
On the receiving end, the receiver monitored NTP traffic and extracted the LI field from the relevant packets. They collected the 4-bit groups from these LI fields and converted them back into the original 3-bit groups by reversing the division and remainder process used during encoding. The fake "1" bit added at the beginning of each character was then stripped off, reverting the data back to the original 8-bit characters. Finally, the receiver combined these characters to reconstruct the original message M.


Results

We successfully managed to encode and send messages using the LI field in NTP packets. The receiver could accurately decode the hidden messages by following our encoding and decoding process. Even if someone was monitoring the LI fields, the data would appear random and meaningless without knowledge of our specific encoding scheme and the shared secret X.


Transmission Performance

For a binary message of 128 bits, we achieved consistent transmission rates averaging around 42 bits per second. Our measurements recorded rates of 43.02 bits/sec, 42.55 bits/sec, and 42.48 bits/sec. This improved speed demonstrated the effectiveness of our encoding strategy in enhancing the covert channel's performance.

Conclusion

Creating a covert storage channel using NTP’s Leap Indicator field was a fascinating project. It showed us how small, underutilized parts of protocols can be exploited for hidden communication. By adding a fake "1" bit, grouping bits efficiently, and avoiding the 11 LI value except for indicating the end of the message, we were able to develop a stealthy and functional covert channel with a respectable data transmission rate.
