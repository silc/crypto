<b>Frequently Asked Questions</b>
<font size="2">
<p>
<font color="#2f486f">Q: What is SILC?</font><br>
A: SILC (Secure Internet Live Conferencing) is a protocol which provides
secure conferencing services in the Internet over insecure channel. SILC
is IRC like although internally they are very different. Biggest
similarity between SILC and IRC is that they both provide conferencing
services and that SILC has almost same commands as IRC. Other than that
they are nothing alike.
<p>
Biggest differences are that SILC is secure what IRC is not in any way.
The network model is also entirely different compared to IRC.
<p>
<font color="#2f486f">Q: Why SILC in the first place?</font><br>
A: Simply for fun, nothing more. An actually for need back then when it
was started. SILC has been very interesting and educational project.
<p>
<font color="#2f486f">Q: Why use SILC? Why not IRC with SSL?</font><br>
A: Sure, that is possible, although, does that secure the entire IRC
network? And does that increase or decrease the lags and splits in the IRC network? Does that provide user based security where some specific private message are secured? Does that provide security where some specific channel messages are secured? Security is not just about applying encryption to traffic and SILC is not just about `encrypting the traffic`. You cannot make insecure protocol suddenly secure just by encrypting the traffic. SILC is not meant to be IRC replacement. IRC is good for some things, SILC is good for same and some other things.
<p>
<font color="#2f486f">Q: Can I use SILC with IRC client? What about can I use IRC with SILC client?</font><br>
A: Answer for both question is no. IRC client is in no way compatible
with SILC server. SILC client cannot currently use IRC but this may
change in the future if IRC support is added to the SILC client. After
that one could use both SILC and IRC with the same client. Although, even
then one cannot talk from SILC network to IRC network. That just is not
possible.
<p>
<font color="#2f486f">Q: Why client/server protocol is based on IRC? Would it be more interesting to implement something extensible and more powerful?</font><br>
A: They are not, not the least. Have you read the protocol specification?
The client superficially resembles IRC client but everything that happens
under the hood is nothing alike IRC. SILC could *never* support IRC
because the entire network toppology is different (hopefully more scalable
and powerful). So no, SILC protocol (client or server) is not based on
IRC. Instead, I've taken good things from IRC and left all the bad things
behind and not even tried to burden myself with the IRC caveats that will
burden IRC and future IRC projects til the end. SILC client resembles IRC
client because it is easier for new users to start using SILC when they
already know all the commands.
<p>
<font color="#2f486f">Q: Why SILC? Why not IRC3?</font><br>
A: Question that is justified no doubt of that. I didn't start doing SILC to be replacement for IRC. SILC was something that didn't exist in 1996 or even today except that SILC is now released. However, I did check out the IRC3 project in 1997 when I started coding and planning the SILC protocol.
<p>
But, IRC3 is problematic. Why? Because it still doesn't exist. The
project is at the same spot where it was in 1997 when I checked it out.
And it was old project back then as well. Couple of months ago I checked
it again and nothing were happening. That's the problem of IRC3 project.
The same almost happened to SILC as well as I wasn't making real progress
over the years. I talked to the original author of IRC, Jarkko Oikarinen,
in 1997 and he directed me to the IRC3 project, although he said that
IRC3 is a lot of talking and not that much of anything else. I am not
trying to put down the IRC3 project but its problem is that no one in the
project is able to make a decision what is the best way to go about
making the IRC3 and I wasn't going to be part of that. The fact is that
if I would've gone to IRC3 project, nor IRC3 or SILC would exist today. I
think IRC3 could be something really great if they just would get their
act together and start coding the thing.
<p>
<font color="#2f486f">Q: How secure SILC really is?</font><br>
A: A good question which I don't have a answer. SILC has been tried to
make as secure as possible. However, there is no security protocol or
security software that has not been vulnerable to some sort of attacks.
SILC is in no means different from this. So, it is suspected that there
are security holes in the SILC. These holes just needs to be found so
that they can be fixed.
<p>
But to give you some parameters of security SILC uses the most secure
crytographic algorithms such as AES, Twofish, Blowfish, RC5, etc. SILC
does not have DES or 3DES as DES is insecure and 3DES is just too slow.
SILC also uses cryptographically strong random number generator when it
needs random numbers. Public key cryptography uses RSA (PKCS #1) and
Diffie Hellman algorithms. Key lengths for ciphers are initially set to
256. For public key algorithms the starting key length is 1024 bits.
<p>
But the best answer for this question is that SILC is as secure as its
weakest link. SILC is open and the protocol is open and in public thus
open for security analyzes.
<p>
To give a list of attacks that are ineffective against SILC:
<p>
<li>Man-in-the-middle attacks are ineffective if proper public key
infrastructure is used. SILC is vulnerable to this attack if the public
keys used in the SILC are not verified to be trusted (as any other
protocol for that matter).
<li>IP spoofing is ineffective (because of encryption and trusted keys).
<li>Attacks that change the contents of the data or add extra data to the
packets are ineffective (because of encryption and integrity checks).
<li>Passive attacks (listenning network traffic) are ineffective (because
of encryption). Everything is encrypted including authentication data
such as passwords when they are needed.
<li>Any sort of cryptanalytic attacks are tried to make ineffective by
using the best cryptographic algorithms out there.
<p>
<i>More to come later...</i>
</font><p>