import com.google.common.io.BaseEncoding;

import java.nio.*;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

public class IdGen
{
    static AtomicLong al = new AtomicLong(1);
    static BaseEncoding be = BaseEncoding.base32Hex().omitPadding();
    static UUID guid = UUID.randomUUID();
    static ByteBuffer buf = ByteBuffer.allocate(8);

    public static final void main(String [] argv)
    {
        for(int i =0; i<256; i++)
        {
            System.err.println(id27());
            System.err.println(id41());
            System.err.println(id55());
            System.err.println(id69());
        }
    }

    public static final String id27()
    {
        StringBuilder sb = new StringBuilder();
        synchronized (buf)
        {
            buf.putLong(0, guid.getLeastSignificantBits()^System.currentTimeMillis()^al.incrementAndGet());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, guid.getMostSignificantBits()^System.nanoTime());
            sb.append(be.encode(buf.array()));
            return sb.toString();
        }
    }

    public static final String id41()
    {
        StringBuilder sb = new StringBuilder();
        synchronized (buf)
        {
            buf.putLong(0, guid.getLeastSignificantBits()^System.currentTimeMillis());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, guid.getMostSignificantBits()^System.nanoTime());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, al.incrementAndGet());
            sb.append(be.encode(buf.array()));
            return sb.toString();
        }
    }

    public static final String id55()
    {
        StringBuilder sb = new StringBuilder();
        synchronized (buf)
        {
            buf.putLong(0, guid.getLeastSignificantBits());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, guid.getMostSignificantBits()^System.currentTimeMillis());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, System.nanoTime());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, al.incrementAndGet());
            sb.append(be.encode(buf.array()));
            return sb.toString();
        }
    }

    public static final String id69()
    {
        StringBuilder sb = new StringBuilder();
        synchronized (buf)
        {
            buf.putLong(0, guid.getLeastSignificantBits());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, guid.getMostSignificantBits());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, System.currentTimeMillis());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, System.nanoTime());
            sb.append(be.encode(buf.array()));
            sb.append("-");
            buf.putLong(0, al.incrementAndGet());
            sb.append(be.encode(buf.array()));
            return sb.toString();
        }
    }
}
