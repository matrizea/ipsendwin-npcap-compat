using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

class PcapProbe {
    [StructLayout(LayoutKind.Sequential)] struct Device {
        public IntPtr next, name, description, addresses;
        public uint flags;
    }
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] static extern IntPtr pcap_lib_version();
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] static extern int pcap_findalldevs(out IntPtr devices, StringBuilder error);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] static extern void pcap_freealldevs(IntPtr devices);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl, CharSet=CharSet.Ansi)] static extern IntPtr pcap_open_live(string device, int snaplen, int promiscuous, int timeout, StringBuilder error);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] static extern int pcap_datalink(IntPtr handle);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] static extern void pcap_close(IntPtr handle);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] static extern int pcap_next_ex(IntPtr handle, out IntPtr header, out IntPtr data);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] static extern IntPtr pcap_geterr(IntPtr handle);
    [StructLayout(LayoutKind.Sequential)] struct BpfProgram { public uint length; public IntPtr instructions; }
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl, CharSet=CharSet.Ansi)] static extern int pcap_compile(IntPtr handle, out BpfProgram filter, string expression, int optimize, uint netmask);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] static extern int pcap_setfilter(IntPtr handle, ref BpfProgram filter);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] static extern void pcap_freecode(ref BpfProgram filter);
    static string Str(IntPtr p) { return p == IntPtr.Zero ? "" : Marshal.PtrToStringAnsi(p); }
    static int Main(string[] args) {
        try {
            if(IntPtr.Size != 4) throw new Exception("Build this probe with /platform:x86.");
            Console.WriteLine("Process bits: " + (IntPtr.Size * 8));
            Console.WriteLine(Str(pcap_lib_version()));
            var error = new StringBuilder(512);
            if(args.Length == 0) {
                IntPtr head;
                if(pcap_findalldevs(out head, error) != 0) throw new Exception(error.ToString());
                try {
                    for(var p = head; p != IntPtr.Zero;) {
                        var d = (Device)Marshal.PtrToStructure(p, typeof(Device));
                        var families = new System.Collections.Generic.List<string>();
                        for(var a = d.addresses; a != IntPtr.Zero; a = Marshal.ReadIntPtr(a)) {
                            var sa = Marshal.ReadIntPtr(a, IntPtr.Size);
                            if(sa != IntPtr.Zero) families.Add(Marshal.ReadInt16(sa).ToString());
                        }
                        Console.WriteLine(Str(d.name) + "\t" + Str(d.description) + "\tAddress families: " + String.Join(",", families.ToArray()));
                        p = d.next;
                    }
                } finally { pcap_freealldevs(head); }
                return 0;
            }
            var h = pcap_open_live(args[0], 2048, 0, 250, error);
            if(h == IntPtr.Zero) throw new Exception(error.ToString());
            try {
                Console.WriteLine("Data link type: " + pcap_datalink(h));
                if(args.Length < 2) return 0;
                if(pcap_datalink(h) != 1) throw new Exception("Capture requires an Ethernet adapter.");
                BpfProgram filter;
                if(pcap_compile(h, out filter, "ether proto 0x88b5", 1, 0xffffffff) != 0) throw new Exception(Str(pcap_geterr(h)));
                try { if(pcap_setfilter(h, ref filter) != 0) throw new Exception(Str(pcap_geterr(h))); }
                finally { pcap_freecode(ref filter); }
                Console.WriteLine("Waiting for a test frame (EtherType 0x88b5), up to 30 seconds.");
                var until = DateTime.UtcNow.AddSeconds(30);
                while(DateTime.UtcNow < until) {
                    IntPtr ph, data;
                    var status = pcap_next_ex(h, out ph, out data);
                    if(status == 0) continue;
                    if(status != 1) throw new Exception(Str(pcap_geterr(h)));
                    if(ph == IntPtr.Zero || data == IntPtr.Zero) throw new Exception("Missing packet buffer.");
                    var captured = Marshal.ReadInt32(ph, 8);
                    if(captured < 14 || captured > 2048) throw new Exception("Unexpected captured length: " + captured);
                    var packet = new byte[captured];
                    Marshal.Copy(data, packet, 0, captured);
                    using(var output = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write))
                        output.Write(packet, 0, packet.Length);
                    Console.WriteLine("Captured test frame: " + captured + " bytes; " + BitConverter.ToString(packet));
                    return 0;
                }
                Console.WriteLine("No test frame received.");
                return 2;
            } finally { pcap_close(h); }
        } catch(Exception e) { Console.Error.WriteLine(e.GetType().Name + ": " + e.Message); return 1; }
    }
}
