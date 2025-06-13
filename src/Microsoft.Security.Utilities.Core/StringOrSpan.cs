// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;

#if NET
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
#endif
using System.Text;

namespace Microsoft.Security.Utilities;

internal struct StringInput
{
#if NET
    private readonly ReadOnlyMemory<char> _memory;

    public ReadOnlyMemory<char> Memory => _memory;

    public ReadOnlySpan<char> Span => _memory.Span;

    public int Length => _memory.Length;

    public char this[int index] => _memory.Span[index];

    public StringInput(string value)
    {
        _memory = value.AsMemory();
    }

    public StringInput(ReadOnlyMemory<char> value)
    {
        _memory = value;
    }

    public int IndexOf(ReadOnlySpan<char> value, StringComparison comparison)
    {
        return Span.IndexOf(value, comparison);
    }

    public int IndexOf(ReadOnlySpan<char> value, int startIndex, StringComparison comparison)
    {
        int index = Span.Slice(startIndex).IndexOf(value, comparison);
        return index < 0 ? index : index + startIndex;
    }

    public string Substring(int start, int length)
    {
        return Span.Slice(start, length).ToString();
    }

    public override string ToString()
    {
        if (TryGetString(out string? str))
        {
            return str;
        }

        return _memory.ToString();
    }

    public bool TryGetString([NotNullWhen(true)] out string? str)
    {
        string? s;
        if (MemoryMarshal.TryGetString(_memory, out s, out int start, out int length) && 
            start == 0 && 
            length == s.Length)
        {
            str = s;
            return true;
        }

        str = null;
        return false;
    }
#else
    private readonly string _value;

    public string String => _value;

    public int Length => _value.Length;

    public char this[int index] => _value[index];

    public StringInput(string value)
    {
        _value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public int IndexOf(string value, StringComparison comparison)
    {
        return _value.IndexOf(value, comparison);
    }

    public int IndexOf(string value, int startIndex, StringComparison comparison)
    {
        return _value.IndexOf(value, startIndex, comparison);
    }

    public string Substring(int start, int length)
    {
        return _value.Substring(start, length);
    }

    public override string ToString()
    {
        return _value;
    }
#endif

    public static implicit operator StringInput(string value)
    {
        return new StringInput(value);
    }

    
}

internal static class StringInputExtensions
{
    public static StringBuilder Append(this StringBuilder builder, StringInput input, int start, int length)
    {
#if NET
        return builder.Append(input.Span.Slice(start, length));
#else
        return builder.Append(input.String, start, length);
#endif
    }
}
