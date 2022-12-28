#ifndef _MASS_HOSTS_ENCODER_H_
#define _MASS_HOSTS_ENCODER_H_

#include <cassert>
#include <string>
#include <vector>
#include <codecvt>

// according to DNS protocol
#define MAX_HOST_NAME_NODE_LEN (64)

class MassHostsEncoder {
  private:
    struct NameNode {
        size_t                offset = 0;
        std::vector<NameNode> childNodes;
    };

    NameNode             root_;
    std::vector<uint8_t> buf_;
    // make sure every determined offset is not zero
    size_t bufCosumed_ = 0x02;

  private:
    int compare_bare_string(const char *a, size_t asize, const char *b, size_t bsize) const {
        auto ret = _strnicmp(a, b, std::min(asize, bsize));
        if (ret != 0) {
            return ret;
        }
        if (asize == bsize) {
            return 0;
        }
        return asize > bsize ? 1 : -1;
    }

    size_t write_string(const std::string_view s) {
        assert(s.size() <= MAX_HOST_NAME_NODE_LEN);
        if (s.size() + 1 + bufCosumed_ >= buf_.size()) {
            // step size = 2048
            auto newSize = ((buf_.size() >> 11) + 1) << 11;
            buf_.resize(newSize);
            if (buf_.empty()) {
                // corrupted
                return -1;
            }
        }

        // save [length, chars]
        auto off = bufCosumed_;
        buf_[bufCosumed_] = (uint8_t)s.size();
        memcpy(&buf_[0] + bufCosumed_ + 1, s.data(), s.size());
        bufCosumed_ += s.size() + 1;
        return off;
    }

    int find_node(const std::vector<NameNode> &nodes, const std::string_view s) const {
        if (nodes.empty()) {
            return -1;
        }
        int low = 0, high = (int)nodes.size() - 1;

        while (low <= high) {
            int  mid = (low + high) / 2;
            auto ret = compare_bare_string((const char *)&buf_[nodes[mid].offset + 1],
                                           buf_[nodes[mid].offset],
                                           s.data(),
                                           s.size());
            if (ret == 0) {
                return (int)mid;
            }
            if (ret < 0) {
                low = mid + 1;
            } else {

                high = mid - 1;
            }
        }
        return -1;
    }

    NameNode *write_node(NameNode *refNode, const std::string_view s) {
        auto foundIdx = find_node(refNode->childNodes, s);
        if (foundIdx != -1) {
            // we found a existed one
            return &refNode->childNodes[foundIdx];
        }

        // write string first of all
        size_t off = write_string(s);
        if (off == -1) {
            return nullptr;
        }

        // find a place to insert
        int insertPos = (int)refNode->childNodes.size() - 1;
        while (insertPos >= 0 &&
               compare_bare_string(
                   (const char *)&buf_[refNode->childNodes[insertPos].offset + 1], // src string ptr
                   buf_[refNode->childNodes[insertPos].offset], // src string length
                   s.data(),                                    // dst string ptr
                   s.size()                                     // dst string length
                   ) > 0) {
            --insertPos;
        }

        // create new node
        NameNode node;
        node.offset = off;
        refNode->childNodes.emplace(refNode->childNodes.begin() + (insertPos + 1), node);
        return &refNode->childNodes[insertPos + 1];
    }

  public:
    //
    // Compress the given host name
    // 1: Write every part of the name into buffer by walking the Trie
    // 2: Save all the corresponding offset
    // 3: Encode the offset list (int32_t) into an UTF-8 seq
    //
    std::string compress_hostname(const std::string_view name) {
        std::vector<int32_t> offList;

        // write all parts
        int       nameOffset = 0;
        NameNode *refNode = &root_;
        int       lastPos = (int)name.size();
        for (int idx = (int)name.size() - 1; idx >= nameOffset; idx--) {
            if (name[idx] == '.') {
                auto len = lastPos - idx - 1;
                if ((refNode = write_node(refNode, {name.data() + idx + 1, (size_t)len})) ==
                    nullptr) {
                    return {};
                }

                // save offset
                offList.emplace_back((int32_t)refNode->offset);

                // move to next part
                lastPos = idx;
            }
        }

        // last part
        if ((refNode =
                 write_node(refNode, {name.data() + nameOffset, (size_t)lastPos - nameOffset})) ==
            nullptr) {
            return {};
        }
        offList.emplace_back((int32_t)refNode->offset);

        // encode offset list (UTF-32) to UTF-8
        std::wstring_convert<std::codecvt_utf8<int32_t>, int32_t> convert;
        return convert.to_bytes(&offList[0], &offList[0] + offList.size());
    }

    //
    // Decompress the given sequence that retrieved from compress_hostname previously
    // 1: Decode UTF-8 seq into UTF-32 seq properly
    // 2: Every single rune of the UTF-32 seq is an offset that point to a name part [length, chars]
    // 3: Read out each part, and that's all.
    //
    std::string decompress_hostname(const std::string_view name) {
        if (name.empty() || buf_.empty()) {
            return {};
        }

        std::wstring_convert<std::codecvt_utf8<int32_t>, int32_t> convert;
        auto offList = convert.from_bytes(&name[0], &name[0] + name.size());
        if (offList.empty()) {
            return {};
        }

        // calculate total length
        size_t totalLen = 0;
        for (int32_t &off : offList) {
            if ((size_t)off >= buf_.size() || buf_[off] + off >= buf_.size()) {
                // invalid sequence
                return {};
            }
            // name length plus the dot
            totalLen += buf_[off] + 1;
        }
        if (--totalLen == 0) {
            // invalid
            return {};
        }

        // prepare space
        std::string result;
        result.resize(totalLen);
        if (result.empty()) {
            return {};
        }

        // extract string
        char *ptr = &result[0] + result.size();
        for (size_t idx = 0; idx < offList.size(); idx++) {
            auto off = (size_t)offList[idx];
            memcpy(ptr - buf_[off], &buf_[off + 1], buf_[off]);
            ptr -= buf_[off];

            if (idx != offList.size() - 1) {
                // append dot
                *(--ptr) = '.';
            }
        }

        // done
        return result;
    }
};

#endif //_MASS_HOSTS_ENCODER_H_