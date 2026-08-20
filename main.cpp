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
    glfwSwapInterval(1);

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

        ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(1280, 720), ImGuiCond_FirstUseEver);
        ImGui::Begin("Wire Sniffer Network Analyser", nullptr, ImGuiWindowFlags_NoCollapse);


        ImGui::BeginChild("PacketListPane", ImVec2(0, ImGui::GetWindowHeight() * 0.5f), true);

        if (ImGui::BeginTable("PacketTable", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("No.");
            ImGui::TableSetupColumn("Time");
            ImGui::TableSetupColumn("Source");
            ImGui::TableSetupColumn("Destination");
            ImGui::TableSetupColumn("Protocol");
            ImGui::TableSetupColumn("Length");
            ImGui::TableSetupColumn("Info");
            ImGui::TableHeadersRow();

            std::lock_guard<std::mutex> lock(g_packetMutex);


            for (const auto& packet : g_packetList) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%d", packet.id);
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", packet.time.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s", packet.source.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s", packet.destination.c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%s", packet.protocol.c_str());
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%d", packet.length);
                ImGui::TableSetColumnIndex(6);
                ImGui::Text("%s", packet.info.c_str());
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();

        ImGui::Columns(2, "BottomPanes");

        ImGui::BeginChild("DetailsPane", ImVec2(0,0), true);
        ImGui::Text("Packet Details");
        ImGui::Separator();

        if (ImGui::TreeNode("Frame 1: 64 bytes on wire")) {
            ImGui::Text("Arrival Time: Aug 20");
            ImGui::TreePop();
        }

        if (ImGui::TreeNode("Ethernet II, Src: 00:11:22:33, Dst: 44:55:66:77")) {
            ImGui::Text("Destination: 44:55:66:77");
            ImGui::Text("Source: 00:11:22:33");
            ImGui::TreePop();
        }

        ImGui::EndChild();
        ImGui::NextColumn();


        ImGui::BeginChild("HexDumpPane", ImVec2(0, 0), true);
        ImGui::Text("Raw Hex Dump");
        ImGui::Separator();

        ImGui::Text("0000 44 45 55 44 66 77 23 00 11 22 33 08 67");
        ImGui::Text("0010 a2 01 43 c4 34 b1 22 67 67 67 22 99 10");
        ImGui::EndChild();

        ImGui::Columns(1);
        ImGui::End();




        ImGui::Render();

        // 5. Clear the OS window background to a solid color (dark grey)
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        // 6. Draw the ImGui memory to the OpenGL window
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}