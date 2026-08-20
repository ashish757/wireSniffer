#include <iostream>
#include <GLFW/glfw3.h>
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "pcap.h"

#include <vector>
#include  <string>
#include <mutex>
#include <thread>
#include <chrono>


struct CapturedPacket {
    int id;
    std::string time;
    std::string source;
    std::string destination;
    std::string protocol;
    int length;
    std::string info;
};




std::vector<CapturedPacket> g_packetList;

std::mutex g_packetMutex;





int g_packetCount = 1;

void packetHandler(u_char *userDta, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    CapturedPacket newPacket;
    newPacket.id = g_packetCount++;
    newPacket.time = "Live";
    newPacket.source = "Unknown";
    newPacket.destination = "Unknown";
    newPacket.protocol = "ETH";
    newPacket.length = pkthdr->len;
    newPacket.info = "Raw Frame Captured";

    std::lock_guard<std::mutex> lock(g_packetMutex);
    g_packetList.push_back(newPacket);

}



bool g_isCapturing =  true;

void CaptureThreadFunc() {
   char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle =  pcap_open_live("en0", 65535, 1, 100, errbuf);

    if (handle == nullptr) {
        std::cerr << "Could not open device: "<<errbuf<<std::endl;
        std::cerr<<"Running with sudo??"<<std::endl;
        return;
    }

    while (g_isCapturing) {
        pcap_dispatch(handle , 10, packetHandler, nullptr);

    }

    pcap_close(handle);

}




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