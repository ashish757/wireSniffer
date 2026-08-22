#include <iostream>
#include <GLFW/glfw3.h>
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <thread>
#include "../include/CaptureHeader.h"


int main() {
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return -1;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);


    GLFWwindow* window = glfwCreateWindow(1280, 720, "Wire Sniffer", nullptr, nullptr);
    if (!window) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return -1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 150");


    std::thread captureThread(CaptureThreadFunc);
    int selectedPacketId = -1;
    CapturedPacket selectedPacketData;
    while (!glfwWindowShouldClose(window)) {

        glfwPollEvents();

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

                char label[32];
                snprintf(label, sizeof(label), "%d", packet.id);
                if (ImGui::Selectable(label, selectedPacketId == packet.id, ImGuiSelectableFlags_SpanAllColumns)) {
                    selectedPacketId = packet.id;
                    selectedPacketData = packet;
                }

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

        ImGui::BeginChild("HexDumpPane");
        ImGui::Text("Raw Hex Dump");
        ImGui::Separator();

        if (selectedPacketId != -1) {
            const auto& data = selectedPacketData.rawData;

            for (size_t i  =0; i<data.size(); i += 16) {
                ImGui::Text("%04zx ", i);
                ImGui::SameLine();


                for (size_t j  =0; j<16; j++) {
                    if (i + j < data.size()) {
                        ImGui::Text("%02x ", data[i + j]);
                    } else {
                        ImGui::Text(" ");
                    }
                    ImGui::SameLine();
                }

            ImGui::Text(" ");
            ImGui::SameLine();

            std::string asciiStr = " ";
            for (size_t j = 0; j<16 && (i+j) < data.size(); j++) {
                char c = data[i+j];
                asciiStr += (c >= 32 && c <= 126) ? c : '.';
            }
                ImGui::Text("%s", asciiStr.c_str());
            }
        } else {
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "Select a packet to view hex dump");
        }

        ImGui::EndChild();

        ImGui::Columns(1);
        ImGui::End();

        ImGui::Render();

        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();


    g_isCapturing = false;
    if (captureThread.joinable()) {
        captureThread.join();
    }


    return 0;
}