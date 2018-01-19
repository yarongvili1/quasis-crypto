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
#include <assert.h>
#include <initializer_list>
#include "string.h"

namespace crypto
{
    template<size_t SIZE, typename word_t = uint8_t>
    class Number
    {
        enum
        {
            WORD = CHAR_BIT * sizeof(word_t),
        };

        word_t        word[ SIZE / WORD ];
        static inline const Number ZERO{};


     public:

        Number() : word{}
        {
        }


        Number(const std::initializer_list<word_t> &object)
        {
            memcpy(this->data(), object.begin(), object.size() * sizeof(word_t));
        }


        template<size_t length, typename type_t>
        Number(const Number<length, type_t> &number) : word{}
        {
            memcpy(this->data(), &number, SIZE <= length ? size() : number.size());
        }


        template<class data_t>
        Number(const data_t &object) : word{}
        {
            assert(this->size() >= sizeof(data_t));
            memcpy(this->data(), &object, sizeof(data_t));
        }


        template<class char_t = char>
        Number(const String<char_t> &string, const String<char_t> &format) : Number(from(string, format))
        {
        }


       ~Number()
        {
            memset(this->data(), 0, this->size());
        }


        size_t
        bits() const
        {
            return SIZE;
        }


        size_t
        size() const
        {
            return this->bits() / CHAR_BIT;
        }


        size_t
        bins() const
        {
            return this->size() / sizeof(word_t);
        }


        word_t*
        data()
        {
            return this->word;
        }


        const word_t*
        data() const
        {
            return this->word;
        }


        // ::sub


        word_t&
        operator[](const size_t &offset)
        {
            return this->word[offset];
        }


        const word_t&
        operator[](const size_t &offset) const
        {
            return this->word[offset];
        }


        // ::add


        Number&
        operator+=(const size_t &rvalue)
        {
            size_t remain(rvalue);

            for (size_t i = 0; i < this->bins() && remain; ++i)
            {
                word[i] = (word_t)(remain += word[i]);
                remain  = (size_t)(remain >> WORD);
            }

            return *this;
        }


        friend Number
        operator+(const Number &lvalue, const size_t &rvalue)
        {
            return Number(lvalue) += rvalue;
        }


        friend Number
        operator+(const size_t &lvalue , const Number &rvalue)
        {
            return Number(rvalue) += lvalue;
        }


        // ::mul


        Number&
        operator*=(const size_t &rvalue)
        {
            size_t remain = 0;

            for (size_t i = 0; i < this->bins(); ++i)
            {
        	    remain += (rvalue) * this->word[i];
        	    word[i] = (word_t)(remain);
	            remain  = (size_t)(remain >> WORD);
            }

            return *this;
        }


        friend Number
        operator*(const Number &lvalue, const size_t &rvalue)
        {
            return Number(lvalue) *= rvalue;
        }


        friend Number
        operator*(const size_t &lvalue , const Number &rvalue)
        {
            return Number(rvalue) *= lvalue;
        }


        // ::div


        size_t
        divide(const size_t &rvalue)
        {
            size_t remain = 0;

            for (int i = int(this->bins() - 1); i >= 0; --i)
            {
                if ((remain <<= WORD) += this->word[i])
                {
                    word[i] = (word_t)(remain / rvalue);
                    remain  = (size_t)(remain % rvalue);
                }
                else
                {
                    word[i] = 0;
                }
            }

            return remain;
        }


        Number&
        operator/=(const size_t &rvalue)
        {
            return (divide(rvalue), *this);
        }


        friend Number
        operator/(const Number &lvalue, const size_t &rvalue)
        {
            return Number(lvalue) /= rvalue;
        }


        // ::not


        bool
        operator!() const
        {
            return memcmp(this->data(), ZERO.data(), this->size()) == 0;
        }


        // ::eql


        friend bool
        operator==(const Number &lvalue, const Number &rvalue)
        {
            return memcmp(lvalue.data(), rvalue.data(), rvalue.size()) == 0;
        }


        // ::neq


        friend bool
        operator!=(const Number &lvalue, const Number &rvalue)
        {
            return memcmp(lvalue.data(), rvalue.data(), rvalue.size()) != 0;
        }


        template<class char_t = char> String<char_t>
        encode(const String<char_t> &format = BASE16) const
        {
            String<char_t>  string;
            Number          number(*this);
            size_t digits = format.size();

            string.reserve(size_t(this->bits() / log2(digits)));

            while (!!number)
            {
                string.push_back(format[number.divide(digits)]);
            }

            if (!string.size()) string.push_back(format[0]);
            return String<>(string.rbegin(), string.rend());
        }


        template<class char_t = char> static Number
        from(const String<char_t> &string, const String<char_t> &format = BASE16)
        {
            Number number;
            size_t digits(format.size()), offset;

            for (const auto &lexeme : string)
            {
                offset = format.find(lexeme);

                if (offset == String<>::npos)
                {
                    return Number();
                }

                (number *= digits) += offset;
            }

            return number;
        }


        void
        unshift(const word_t &number)
        {
            for (size_t i = this->bins() - 1; i >= 1; --i)
            {
                this->word[i] = this->word[i - 1];
            }

            this->word[0] = number;
        }
    };


    // rotl()


    inline uint32_t
    rotl(const uint32_t &number, const int &length)
    {
        #if defined(_WIN32)
            return _lrotl(number, length);
        #else
            return (number << length) | (number >> (32 - length));
        #endif
    }


    inline uint64_t
    rotl(const uint64_t &number, const int &length)
    {
        #if defined(_WIN32)
            return _rotl64(number, length);
        #else
            return (number << length) | (number >> (64 - length));
        #endif
    }


    // rotr()


    uint32_t
    rotr(const uint32_t &number, const int &length)
    {
        #if defined(_WIN32)
            return _lrotr(number, length);
        #else
            return (number >> length) | (number << (32 - length));
        #endif
    }


    uint64_t
    rotr(const uint64_t &number, const int &length)
    {
        #if defined(_WIN32)
            return _rotr64(number, length);
        #else
            return (number >> length) | (number << (64 - length));
        #endif
    }


    // cho3()


    template<typename uint_t> uint_t
    cho3(const uint_t &value1, const uint_t &value2, const uint_t &value3)
    {
        return (value1 & (value2 ^ value3)) ^ value3;
    }


    // maj3()


    template<typename uint_t> uint_t
    maj3(const uint_t &value1, const uint_t &value2, const uint_t &value3)
    {
        return (value1 & value2) | ((value1 ^ value2) & value3);
    }


    // swap()


    uint8_t
    swap(const uint8_t &number)
    {
        return number;
    }


    uint16_t
    swap(const uint16_t &number)
    {
        #if defined(_WIN32)
            return _byteswap_ushort( number );
        #elif defined(__linux__)
            return __builtin_bswap16( number );
        #else
            #error "Architecture not supported."
        #endif
    }


    uint32_t
    swap(const uint32_t &number)
    {
        #if defined(_WIN32)
            return _byteswap_ulong( number );
        #elif defined(__linux__)
            return __builtin_bswap32( number );
        #else
            #error "Architecture not supported."
        #endif
    }


    uint64_t
    swap(const uint64_t &number)
    {
        #if defined(_WIN32)
            return _byteswap_uint64( number );
        #elif defined(__linux__)
            return __builtin_bswap64( number );
        #else
            #error "Architecture not supported."
        #endif
    }


    template<size_t SIZE, typename word_t> Number<SIZE, word_t>
    swap(const Number<SIZE, word_t> &number)
    {
        Number<SIZE, word_t> result;

        for (size_t i = 0; i < number.bins(); ++i)
        {
            result[i] = swap(number[number.bins() - i - 1]);
        }

        return result;
    }


    #if BYTE_ORDER == LITTLE_ENDIAN
        #define h2le(x) (x)
        #define h2be(x) swap(x)
        #define le2h(x) (x)
        #define be2h(x) swap(x)
    #elif BYTE_ORDER == BIG_ENDIAN
        #define h2le(x) swap(x)
        #define h2be(x) (x)
        #define le2h(x) swap(x)
        #define be2h(x) (x)
    #else
        #error "Architecture not supported."
    #endif


    #if SIZE_MAX == UINT32_MAX
        typedef Number<128, uint16_t> uint128_t;
        typedef Number<160, uint16_t> uint160_t;
        typedef Number<256, uint16_t> uint256_t;
        typedef Number<512, uint16_t> uint512_t;
    #elif SIZE_MAX == UINT64_MAX
        typedef Number<128, uint32_t> uint128_t;
        typedef Number<160, uint32_t> uint160_t;
        typedef Number<256, uint32_t> uint256_t;
        typedef Number<512, uint32_t> uint512_t;
    #else
        #error "Architecture not supported."
    #endif
}
