<b>History</b>
<font size="2">
<p>
Even though SILC were released in summer 2000 to the public the idea and the protocol itself is quite old. I got the idea about SILC in its current form in the year 1996 and first lines of codes were written in early 1997. This release is now third rewrite of the SILC. The very first version were written in 1997 and it included SILC client and very very preliminary SILC server. The server actually weren't usable but the client looked pretty much the same as it does now. At that time the SILC also included RSA implementation and 3DES implementation. The random number generator that exists in this current release is actually based on the RNG written in 1997. The RNG written in 1997, on the other hand, were based on the SSH's random number generator. The RNG has been rewritten twice since the first version.
<p>
I stopped writing the SILC later in 1997 when I got busy at school and in work. The pause lasted several months. The development resumed in 1998 when my friend (Juha R�s�nen) and I implemented ElGamal algorithm. I rewrote some other parts as well. However, for the same reasons as previously the development stopped again. I resumed the development later in 1998 by doing rewrite of the SILC in C++. This was obviously a mistake but at that time it seemed like a good idea. Again, in the winter 1999 I got very busy writing my thesis and was forced to stop the development again. I also, started a new job in the spring.
<p>
Later, in 1999, I decided that this time I'm going to make it the right way. C++ was obviously a bad choice so I decided to fall back to plain C language. I also decided to do complete rewrite and started doing more thorough planning of what the SILC actually should include. I also decided that this time it is going to kill me before I stop the development. I started writing SILC in the weekends and actually everytime I had some spare time. I also started a new job but I didn't let that get to my way. The result of this development effort is the release now in public.
<p>
I've learned a lot by doing the SILC. I guess, when I started it I wasn't that good of a C programmer. That alone was a reason why SILC hasn't seen the day of light before now. My programming style has also changed dramatically during these years. Actually, it has changed couple times since this last rewrite as well. However, the code style of current SILC release is quite consistent (actually the coding style SILC has been written now I've learned in my current job).
<p>
There is probably over 85% of new code in this third rewrite. Rest has just been copied from the old versions and only minor changes has been made (like changed function names and overall coding style). I've preserved the dates of the old files (dating back to 1997) that has existed in some forms in the old versions. There is a lot of new code but already I see a lot that needs rewriting. The development continues.
</font><p>