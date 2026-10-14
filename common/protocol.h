#pragma once

#include <cstddef>
#include <cstdint>

namespace protocol
{
constexpr std::uint32_t kMaxFrameSize = 64 * 1024;
constexpr std::size_t kPublicKeySize = 32;

constexpr unsigned char kMsgRegister = 0x01;
constexpr unsigned char kMsgSend = 0x02;
constexpr unsigned char kMsgDeliver = 0x03;
constexpr unsigned char kMsgOk = 0x10;
constexpr unsigned char kMsgError = 0x11;

constexpr unsigned char kErrBadFrame = 1;
constexpr unsigned char kErrUnknownType = 2;
constexpr unsigned char kErrNotOnline = 3;
}