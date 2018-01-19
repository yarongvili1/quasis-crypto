/*
 * MIT License
 *
 * Copyright (c) 2018 Quasis (info@quasis.io)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#pragma once
#include "../number.h"
#include "../string.h"

namespace crypto
{
    template<size_t BASE> auto
    rmd(const void *record, const size_t &length)
    {
        return hasher::RMD<BASE>().update(record, length).digest();
    }


    template<size_t BASE, size_t length> auto
    rmd(const Number<length> &number)
    {
        return rmd<BASE>(number.data(), number.size());
    }


    template<size_t BASE, class char_t> auto
    rmd(const String<char_t> &string)
    {
        return rmd<BASE>(string.data(), string.size());
    }


    template<size_t BASE, class data_t> auto
    rmd(const data_t &object)
    {
        return rmd<BASE>((void*)&object, sizeof(data_t));
    }


    namespace hasher
    {
        template<size_t BASE>
        class RMD
        {
            typedef uint8_t  byte_t;
            typedef uint32_t word_t;

            Number<BASE, word_t>              hash;
            Number<ATOM, byte_t>              atom;
            size_t                            offs;
            size_t                            size;

        public:

            static const Number<BASE, word_t> SEED;
            static const Number<ITER, word_t> SALT;


            RMD() : hash{RMD::SEED}, offs(0), size(0)
            {
            }


           ~RMD()
            {
                this->size = this->offs = 0;
            }


            RMD&
            update(const void *record, const size_t &length)
            {
                return this->insert((byte_t*)record, length);
            }


            template<size_t length> RMD&
            update(const Number<length> &number)
            {
                return update(number.data(), number.size());
            }


            template<class char_t> RMD&
            update(const String<char_t> &string)
            {
                return update(string.data(), string.size());
            }


            template<class data_t> RMD&
            update(const data_t &object)
            {
                return update((void*)&object, sizeof(data_t));
            }


            Number<SIZE>
            digest()
            {
                return this->offs == BASE ? this->hash : finish();
            }


        private:

            byte_t*
            front()
            {
                return std::addressof(this->atom[this->offs]);
            }


            size_t
            capacity() const
            {
                return size_t(this->atom.size() - this->offs);
            }


            RMD&
            insert(const byte_t *record, const size_t &length)
            {
                size_t  volume, offset = 0, remain = length;

                while ((volume = this->capacity()) <= remain)
                {
                    memcpy(this->front(), record + offset, volume);
                    encode(); remain -= volume; offset += volume;
                }

                memcpy(this->front(), record + offset, remain);
                this->offs += remain; this->size += length;
                return *this;
            }


            RMD&
            insert(const size_t &length, const byte_t &record = 0)
            {
                size_t  volume, remain = length;

                while ((volume = this->capacity()) <= remain)
                {
                    memset(this->front(), record, volume);
                    this->encode(); remain -= volume;
                }

                memset(this->front(), record, remain);
                this->offs += remain; this->size += length;
                return *this;
            }


            void
            encode()
            {
                Number<BASE, word_t>  digest{this->hash};
                Number<ITER, word_t>  pseudo{this->atom};

                for (size_t i = 00U; i < size_t(16U); ++i)
                {
                    pseudo[i] = h2be(pseudo[i]);
                }

                for (size_t i = 16U; i < pseudo.bins(); ++i)
                {
                    pseudo[i] = pseudo[i-16U] + sigma0(pseudo[i-15U]) + pseudo[i-7U] + sigma1(pseudo[i-2U]);
                }

                for (size_t i = 00U; i < pseudo.bins(); ++i)
                {
                    word_t t1 = pseudo[i] + RMD<BASE,BASE>::SALT[i] + digest[7U] +
                                delta1(digest[4U]) + cho3(digest[4U], digest[5U], digest[6U]);
                    word_t t2 = delta0(digest[0U]) + maj3(digest[0U], digest[1U], digest[2U]);

                    digest[7U] = digest[6U]; digest[6U] = digest[5U];
                    digest[5U] = digest[4U]; digest[4U] = digest[3U] + t1;
                    digest[3U] = digest[2U]; digest[2U] = digest[1U];
                    digest[1U] = digest[0U]; digest[0U] = t1 + t2;

                    //digest.unshift(t1 + t2), digest[4] += t1;
                }

                for (size_t i = 00U; i < digest.bins(); ++i)
                {
                    this->hash[i] += digest[i];
                }

                this->offs = 0;
            }


            Number<SIZE>
            finish()
            {
                long_t length = h2be(long_t(size) * CHAR_BIT);
                size_t offset = atom.size( ) - sizeof(long_t);

                if (insert(1, byte_t(0x80)), this->offs > offset)
                {
                    this->insert(this->capacity());
                }

                this->insert(offset - this->offs).update(length);

                for (size_t i = 0U; i < this->hash.bins(); ++i)
                {
                    this->hash[i] = be2h(this->hash[i]);
                }

                this->offs = BASE;
                return this->hash;
            }


            static uint32_t
            sigma0(const uint32_t &number)
            {
                return rotr(number, 7) ^ rotr(number,18) ^ (number >>  3);
            }


            static uint64_t
            sigma0(const uint64_t &number)
            {
                return rotr(number, 1) ^ rotr(number, 8) ^ (number >>  7);
            }


            static uint32_t
            sigma1(const uint32_t &number)
            {
                return rotr(number,17) ^ rotr(number,19) ^ (number >> 10);
            }


            static uint64_t
            sigma1(const uint64_t &number)
            {
                return rotr(number,19) ^ rotr(number,61) ^ (number >>  6);
            }


            static uint32_t
            delta0(const uint32_t &number)
            {
                return rotr(number, 2) ^ rotr(number,13) ^ rotr(number,22);
            }


            static uint64_t
            delta0(const uint64_t &number)
            {
                return rotr(number,28) ^ rotr(number,34) ^ rotr(number,39);
            }


            static uint32_t
            delta1(const uint32_t &number)
            {
                return rotr(number, 6) ^ rotr(number,11) ^ rotr(number,25);
            }


            static uint64_t
            delta1(const uint64_t &number)
            {
                return rotr(number,14) ^ rotr(number,18) ^ rotr(number,41);
            }
        };


        // RMD<160>

        template<>
        decltype(RMD<160>::SEED) RMD<160>::SEED =
        {
            0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
        };


        template<>
        decltype(RMD<160>::SALT) RMD<160>::SALT =
        {
        };
    }
}
