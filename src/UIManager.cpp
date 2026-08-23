//
// Created by Ashish Raj Singh on 22/08/26.
//

#include "../include/UIManager.h"
#include "imgui.h"
#include "imgui_internal.h"
#include <arpa/inet.h>
#include <netinet/in.h>


void UIManager::Render() {

    ImGuiIO& io = ImGui::GetIO();

    // io.Fonts->AddFontFromFileTTF("fonts/JetBrainsMono-Regular.ttf", 16.0f);

    ImGui::SetNextWindowPos(ImVec2(0.0f,0.0f));
    ImGui::SetNextWindowSize(io.DisplaySize);

    ImGui::StyleColorsLight();

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.FrameRounding = 2.0f;
    style.ItemSpacing = ImVec2(8,8);

    ImGuiWindowFlags windowFlags =
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoBringToFrontOnFocus;

    ImGui::Begin("Wire Sniffer Network Analyser", nullptr, windowFlags);

    if (ImGui::BeginTabBar("MainTabs")) {
        if (ImGui::BeginTabItem("Traffic Analyzer")) {
            ImGui::BeginChild("PacketListPane", ImVec2(0, packetListHeight), true);
            DrawPacketList();
            ImGui::EndChild();

            ImGui::InvisibleButton("v_splitter", ImVec2(-1, 8.0f));
            if (ImGui::IsItemHovered()) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
            if (ImGui::IsItemActive()) packetListHeight+=io.MouseDelta.y;


            ImGui::Columns(2, "BottomPanes");
            DrawDetailsPane();
            ImGui::NextColumn();
            DrawHexDumpPane();
            ImGui::Columns(1);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Active Tools")) {
            DrawInjectionPane();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}


void UIManager::DrawPacketList() {

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
        for (const auto& packet: g_packetList) {
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
}



void UIManager::DrawDetailsPane() {
    ImGui::BeginChild("DetailsPane", ImVec2(0,0), true);
    ImGui::Text("Packet Details");
    ImGui::Separator();

    if (selectedPacketId != -1) {
        ImGui::Text("Frame Length: %d bytes", selectedPacketData.length);
        ImGui::Text("Captured on Interface: en0");
    } else {
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "Select a packet to view details");
    }
    ImGui::EndChild();
}


void UIManager::DrawHexDumpPane() {
    ImGui::BeginChild("HexDumpPane", ImVec2(0,0), true);
    ImGui::Text("Raw Hex Dump");
    ImGui::Separator();

    if (selectedPacketId != -1) {
        const auto& data = selectedPacketData.rawData;
        for (size_t i = 0; i < data.size(); i += 16) {
            ImGui::Text("%04zx ", i);
            ImGui::SameLine();

            for (size_t j = 0; j < 16; j++) {
                if (i+j<data.size()) {
                    ImGui::Text("%02X ", data[i+j]);
                } else {
                    ImGui::Text("   ");
                }
                ImGui::SameLine();
            }
            ImGui::Text("  ");
            ImGui::SameLine();

            std::string asciiStr = " ";
            for (size_t j = 0; j < 16 && (i + j) < data.size(); j++) {
                char c = data[i + j];
                asciiStr += (c >= 32 && c <= 126) ? c : '.';
            }
            ImGui::Text("%s", asciiStr.c_str());
        }

    } else {
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "Select a packet to view details");

    }
    ImGui::EndChild();

}


void UIManager::DrawInjectionPane() {
    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "ARP Spoofing Engine");
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::InputText("Target IP (victim)", targetInBuffer, sizeof(targetInBuffer));
    ImGui::InputText("Router IP (gateway", routerIpBuffer, sizeof(routerIpBuffer));
    ImGui::InputText("Attacker MAC (you)", attackerMacBuffer, sizeof(attackerMacBuffer));

    if (ImGui::Button("Build & Fire", ImVec2(-1, 30))) {
        struct in_addr targetAddr{};
        struct in_addr routerAddr{};

        bool targetValid = inet_pton(AF_INET, targetInBuffer, &targetAddr) == 1;
        bool routerValid = inet_pton(AF_INET, routerIpBuffer, &routerAddr) == 1;

        if (!targetValid || !routerValid) {
            injectionStatus = "Invalid IPv4 Address";
        } else {
            EthernetHeader ethernet{};
            ARPHeader arp{};

            std::memset(ethernet.dest, 0xff, 6);
            std::memset(ethernet.src, 0, 6);
            ethernet.type = htons(0x0806);

            arp.hardware_type = htons(1);
            arp.protocol_type = htons(0x0800);
            arp.hardware_len = 6;
            arp.protocol_len  = 4;
            arp.opcode = htons(2);

            std::memset(arp.sender_mac, 0, 6);
            arp.sender_ip = routerAddr.s_addr;

            std::memset(arp.target_mac, 0, 6);
            arp.target_ip = targetAddr.s_addr;

            ARPFrame frame = buildFrame(ethernet, arp);

            injectionStatus = "Frane Built Successfully in memory (" + std::to_string(frame.size()) + "bytes)";
        }
    }
    if (!injectionStatus.empty()) {
        ImGui::Separator();
        ImGui::TextWrapped("Status: %s", injectionStatus.c_str());
    }
}