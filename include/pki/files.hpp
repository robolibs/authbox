#pragma once

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace authbox {
    namespace io {

        struct BinaryReadResult {
            bool success = false;
            std::vector<uint8_t> data;
            std::string error_message;
        };

        inline BinaryReadResult read_binary(const std::string &path) {
            std::ifstream file(path, std::ios::binary);
            if (!file.is_open()) {
                return {false, {}, "Failed to open file: " + path};
            }

            std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (file.bad()) {
                return {false, {}, "Failed to read file: " + path};
            }

            return {true, std::move(data), ""};
        }

        inline bool write_binary(const std::vector<uint8_t> &data, const std::string &path) {
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!file.is_open()) {
                return false;
            }

            file.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
            return file.good();
        }

    } // namespace io
} // namespace authbox

namespace keylock::io {
    using authbox::io::BinaryReadResult;
    using authbox::io::read_binary;
    using authbox::io::write_binary;
} // namespace keylock::io
