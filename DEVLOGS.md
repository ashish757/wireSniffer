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
