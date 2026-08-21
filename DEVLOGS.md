# Devlog 1
i have setup basic project
## UI Framwework
- QT -> this felt too heavy for techy spy website, also i dont need this much of features and its compilation process, i read it twice and still it went above my head
- dear imgui -> this is light weight and its a immediate mode ui, something which i treid to learn last time when i build a CHIP8-Emulator

- i also used GLFW to create windows and handle I/O

> thats all, till next devlog i plan to remove th demo UI of dear imgui, and implement a simple placeholder UI


# Devlog 2

- ## Improved UI Layout
- Layout sections can now be resized will work later on making them responsive automatically

- Now this UI rendering is different from websites rendering
- here the whole UI is erased and redrawn 60 times every second, and i i put a blocking process in this UI loop, the my ui will become unresponsive
- to fix this i used thread to run the monitoring of network in background
- used std::mutex to prevent read and write happening at same time
- libpcap is used to process the packets in batches

> next, i would like to make ui more responsive and display more information about the packets and network
![img.png](img.png)


# Devlog 3
These low level languages, they are fucking scary. I spent my like 90% of time debugging and understanding the theory behind this networks and specifically how libcap handles them, then writing actual code.  banging my head to AI to explain me these things.

## Heres what i got
- first of all i did a quick revison of pointer stuff as the libcap is usign that heavily
- Theres one thing i dont understand completely which is `#pragma pack(push, 1)` it is some deep memory thing, i read about it but did note really understand this, got AI help here
- used pointer arithmatics to extract the details of packet
- Also i found some cool things like big-endian and little endian, won't talk much about this, but i guess i feel like a network engineer already

### Well if you did not read the stuff above, Here's the cool thing in one line Right now, the UI properly displays IP addresses, exact ports, and connection details.

> I don't know what I'm gonna do next because it was a lot of time and researching and learning in last session so probably I will take a break and after that i wil just look into what else is there, i  guess there is a lot of still remaining network can't be easy, but let's see.