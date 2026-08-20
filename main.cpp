#include <iostream>
// Include GLFW for window creation
#include <GLFW/glfw3.h>
// Include ImGui core and backend headers
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

int main() {
    // ========================================================================
    // PHASE 1: INITIALIZATION
    // ========================================================================

    // 1. Initialize GLFW. If it fails, the OS graphics can't be used.
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return -1;
    }

    // Tell GLFW we want to use OpenGL 3.2 (Standard for macOS)
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE); // Required on Mac

    // Create the actual OS window (Width, Height, Title)
    GLFWwindow* window = glfwCreateWindow(1280, 720, "Wire Sniffer v0.1", nullptr, nullptr);
    if (!window) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return -1;
    }
    // Make this window the primary one we are drawing to
    glfwMakeContextCurrent(window);
    // Enable vsync (locks framerate to your monitor's refresh rate)
    glfwSwapInterval(1);

    // Initialize ImGui Context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    // Setup ImGui to use dark mode (perfect for hacker tools)
    ImGui::StyleColorsDark();

    // Bind ImGui to our GLFW window and OpenGL pipeline
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    // ========================================================================
    // PHASE 2: THE MAIN RENDER LOOP (Runs 60 frames per second)
    // ========================================================================

    // Keep looping until the user clicks the close button on the window
    while (!glfwWindowShouldClose(window)) {

        // 1. Listen for OS events (mouse clicks, keyboard presses, window resizing)
        glfwPollEvents();

        // 2. Tell ImGui a new frame is starting
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // 3. --- THIS IS WHERE WE BUILD OUR UI ---
        // We call ImGui::ShowDemoWindow() for now. It generates a massive window
        // showing every single button, table, and feature ImGui has.
        ImGui::ShowDemoWindow();

        // 4. Render the UI to memory
        ImGui::Render();

        // 5. Clear the OS window background to a solid color (dark grey)
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        // 6. Draw the ImGui memory to the OpenGL window
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        // 7. Swap the buffers (Display the newly drawn frame on the monitor)
        glfwSwapBuffers(window);
    }

    // ========================================================================
    // PHASE 3: CLEANUP
    // ========================================================================

    // Safely shut down all the graphics subsystems to prevent memory leaks
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}