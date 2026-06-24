#include <gtest/gtest.h>
#include "HashUtils.h"

#include <fstream>
#include <cstdio>
#include <cstring>

TEST(HashUtilsTest, EmptyFileHash)
{
    const std::string filename = "test_empty.bin";

    {
        std::ofstream file(filename, std::ios::binary);
    }

    std::string hash = HashUtils::sha256File(filename);

    EXPECT_EQ(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    std::remove(filename.c_str());
}

TEST(HashUtilsTest, KnownStringHash)
{
    const char* data = "abc";

    std::string hash = HashUtils::sha256Bytes(
        reinterpret_cast<const unsigned char*>(data),
        strlen(data)
    );

    EXPECT_EQ(
        hash,
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    );
}

TEST(HashUtilsTest, BytesHashLength)
{
    const char* data = "Digital Signature Test 2026";

    std::string hash = HashUtils::sha256Bytes(
        reinterpret_cast<const unsigned char*>(data),
        strlen(data)
    );

    EXPECT_FALSE(hash.empty());
    EXPECT_EQ(hash.size(), 64);
}

TEST(HashUtilsTest, FileAndBytesConsistency)
{
    const std::string content =
        "Consistency test for DigitalSigner project";

    const std::string filename = "consistency.bin";

    {
        std::ofstream file(filename, std::ios::binary);
        file.write(content.data(), content.size());
    }

    std::string hashFromFile =
        HashUtils::sha256File(filename);

    std::string hashFromBytes =
        HashUtils::sha256Bytes(
            reinterpret_cast<const unsigned char*>(
                content.data()),
            content.size());

    EXPECT_EQ(hashFromFile, hashFromBytes);

    std::remove(filename.c_str());
}

TEST(HashUtilsTest, DifferentInputsProduceDifferentHashes)
{
    const char* data1 = "hello";
    const char* data2 = "hello!";

    std::string hash1 =
        HashUtils::sha256Bytes(
            reinterpret_cast<const unsigned char*>(data1),
            strlen(data1));

    std::string hash2 =
        HashUtils::sha256Bytes(
            reinterpret_cast<const unsigned char*>(data2),
            strlen(data2));

    EXPECT_NE(hash1, hash2);
}

TEST(HashUtilsTest, NonExistingFile)
{
    std::string hash =
        HashUtils::sha256File(
            "file_that_does_not_exist.bin");

    EXPECT_TRUE(hash.empty());
}

TEST(HashUtilsTest, FileSizeCheck)
{
    const std::string filename = "size_test.bin";

    {
        std::ofstream file(filename, std::ios::binary);
        file << "1234567890";
    }

    EXPECT_EQ(
        HashUtils::fileSize(filename),
        10
    );

    std::remove(filename.c_str());
}