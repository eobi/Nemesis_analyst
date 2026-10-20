// NemesisStatic.java — Nemesis Analyst static worker (Ghidra headless).
// Extracts functions, strings (categorized), suspicious-API xrefs, control-flow
// ANOMALIES, and derives DYNAMIC HINTS that tell the dynamic stage where to break.
// Writes a single JSON file. Arg 0 = output path.
//
// @category Nemesis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class NemesisStatic extends GhidraScript {

    static final String[] SUS_APIS = {
        "VirtualAlloc","VirtualProtect","VirtualAllocEx","WriteProcessMemory","ReadProcessMemory",
        "CreateRemoteThread","NtUnmapViewOfSection","SetThreadContext","QueueUserAPC",
        "LoadLibraryA","LoadLibraryW","GetProcAddress","LdrLoadDll","GetModuleHandleA",
        "CreateProcessA","CreateProcessW","WinExec","ShellExecuteA","system",
        "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","OutputDebugStringA",
        "InternetOpenA","InternetConnectA","HttpOpenRequestA","URLDownloadToFileA","WinHttpOpen","connect","send",
        "RegSetValueExA","RegCreateKeyExA","CreateServiceA","SetWindowsHookExA",
        "CryptEncrypt","CryptDecrypt","CreateMutexA","CreateMutexW"
    };
    static final Set<String> ANTIDBG = new HashSet<>(Arrays.asList(
        "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","OutputDebugStringA"));
    static final Set<String> RESOLVE = new HashSet<>(Arrays.asList(
        "GetProcAddress","LoadLibraryA","LoadLibraryW","LdrLoadDll"));

    static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    static String arr(List<String> items) {
        return "[" + String.join(",", items) + "]";
    }
    static String strArr(Collection<String> items) {
        List<String> q = new ArrayList<>();
        for (String s : items) q.add("\"" + esc(s) + "\"");
        return arr(q);
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args != null && args.length > 0) ? args[0] : "nemesis_static.json";

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();

        int funcCount = 0;
        try { for (Function f : fm.getFunctions(true)) funcCount++; } catch (Exception e) {}

        // ---- control-flow anomalies ----
        List<String> anomalies = new ArrayList<>();
        int cap = 500;
        try {
            InstructionIterator it = listing.getInstructions(true);
            Instruction prev = null;
            while (it.hasNext()) {
                Instruction ins = it.next();
                String mn = ins.getMnemonicString().toUpperCase();
                try {
                    if ((mn.equals("CALL") || mn.equals("JMP")) && ins.getNumOperands() >= 1) {
                        int t = ins.getOperandType(0);
                        if (OperandType.isRegister(t) && !OperandType.isAddress(t) && !OperandType.isScalar(t)) {
                            if (anomalies.size() < cap) {
                                Function cf = fm.getFunctionContaining(ins.getAddress());
                                anomalies.add(anom("indirect_register", ins.getAddress().toString(),
                                        cf != null ? cf.getName() : "",
                                        mn + " " + ins.getDefaultOperandRepresentation(0),
                                        "indirect control transfer through a register — resolve target at runtime"));
                            }
                        }
                    }
                    if (mn.equals("RET") && prev != null && prev.getMnemonicString().equalsIgnoreCase("PUSH")
                            && prev.getNumOperands() >= 1) {
                        int pt = prev.getOperandType(0);
                        if (OperandType.isScalar(pt) || OperandType.isAddress(pt)) {
                            if (anomalies.size() < cap) {
                                Function cf = fm.getFunctionContaining(prev.getAddress());
                                anomalies.add(anom("push_ret", prev.getAddress().toString(),
                                        cf != null ? cf.getName() : "",
                                        "PUSH " + prev.getDefaultOperandRepresentation(0) + " ; RET",
                                        "ret-based control transfer (anti-disassembly / obfuscation)"));
                            }
                        }
                    }
                } catch (Exception e) {}
                prev = ins;
            }
        } catch (Exception e) {}

        // ---- suspicious API xrefs ----
        Set<String> susSet = new HashSet<>(Arrays.asList(SUS_APIS));
        List<String> apiXrefs = new ArrayList<>();
        Set<String> apisSeen = new TreeSet<>();
        try {
            SymbolTable st = currentProgram.getSymbolTable();
            SymbolIterator sit = st.getAllSymbols(false);
            while (sit.hasNext()) {
                Symbol s = sit.next();
                String nm = s.getName();
                if (!susSet.contains(nm)) continue;
                Reference[] refs = getReferencesTo(s.getAddress());
                for (Reference r : refs) {
                    apisSeen.add(nm);
                    if (apiXrefs.size() < 400) {
                        Function cf = fm.getFunctionContaining(r.getFromAddress());
                        apiXrefs.add("{\"api\":\"" + esc(nm) + "\",\"from\":\"" + r.getFromAddress()
                                + "\",\"func\":\"" + esc(cf != null ? cf.getName() : "") + "\"}");
                    }
                }
            }
        } catch (Exception e) {}

        // ---- categorized strings ----
        Set<String> urls = new LinkedHashSet<>(), ips = new LinkedHashSet<>(),
                reg = new LinkedHashSet<>(), paths = new LinkedHashSet<>(), susStr = new LinkedHashSet<>();
        int stringCount = 0;
        Pattern urlRe = Pattern.compile("(?i)\\b(?:https?|ftp)://[\\w.\\-/%?=&:#@]+");
        Pattern ipRe = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        String[] susKw = {"cmd.exe","powershell","rundll32","schtasks","regsvr32","mshta",
                "gate.php","/gate","bot","\\\\.\\pipe\\",".onion","mutex","CurrentVersion\\Run"};
        try {
            DataIterator di = listing.getDefinedData(true);
            while (di.hasNext()) {
                Data d = di.next();
                if (!d.hasStringValue()) continue;
                Object v = d.getValue();
                if (v == null) continue;
                String str = v.toString();
                if (str.length() < 4) continue;
                stringCount++;
                if (stringCount > 40000) break;
                Matcher mu = urlRe.matcher(str);
                boolean hit = false;
                while (mu.find() && urls.size() < 200) { urls.add(mu.group()); hit = true; }
                Matcher mi = ipRe.matcher(str);
                while (mi.find() && ips.size() < 200) {
                    String ip = mi.group();
                    if (!ip.startsWith("0.") && !ip.equals("127.0.0.1")) { ips.add(ip); hit = true; }
                }
                String low = str.toLowerCase();
                if ((str.startsWith("HKEY") || low.contains("\\software\\") || low.contains("currentversion\\run"))
                        && reg.size() < 200) { reg.add(str); hit = true; }
                if ((low.endsWith(".exe") || low.endsWith(".dll") || low.contains("c:\\") || low.contains("\\appdata\\"))
                        && paths.size() < 200) { paths.add(str); hit = true; }
                for (String kw : susKw) {
                    if (low.contains(kw.toLowerCase()) && susStr.size() < 200) { susStr.add(str); hit = true; break; }
                }
            }
        } catch (Exception e) {}

        // ---- dynamic hints ----
        List<String> hints = new ArrayList<>();
        int indirectCount = 0;
        for (String a : anomalies) if (a.contains("indirect_register")) indirectCount++;
        // one hint per indirect-register site (cap a few, note the rest)
        int added = 0;
        try {
            InstructionIterator it2 = listing.getInstructions(true);
            while (it2.hasNext() && added < 20) {
                Instruction ins = it2.next();
                String mn = ins.getMnemonicString().toUpperCase();
                if ((mn.equals("CALL") || mn.equals("JMP")) && ins.getNumOperands() >= 1) {
                    int t = ins.getOperandType(0);
                    if (OperandType.isRegister(t) && !OperandType.isAddress(t) && !OperandType.isScalar(t)) {
                        hints.add(hint("breakpoint", ins.getAddress().toString(),
                                "indirect " + mn.toLowerCase() + " via register; break to resolve the real target"));
                        added++;
                    }
                }
            }
        } catch (Exception e) {}
        if (apisSeen.stream().anyMatch(RESOLVE::contains))
            hints.add(hint("api_watch", "GetProcAddress",
                    "dynamic API resolution present; break on GetProcAddress/LoadLibrary to recover resolved APIs"));
        if (apisSeen.stream().anyMatch(ANTIDBG::contains))
            hints.add(hint("anti_analysis", "",
                    "anti-debug APIs imported; run with ScyllaHide and expect timing/debugger checks"));

        // ---- assemble JSON ----
        StringBuilder j = new StringBuilder();
        j.append("{");
        j.append("\"program\":\"").append(esc(currentProgram.getName())).append("\",");
        j.append("\"function_count\":").append(funcCount).append(",");
        j.append("\"anomaly_count\":").append(anomalies.size()).append(",");
        j.append("\"indirect_register_count\":").append(indirectCount).append(",");
        j.append("\"anomalies\":").append(arr(anomalies)).append(",");
        j.append("\"suspicious_apis\":").append(strArr(apisSeen)).append(",");
        j.append("\"suspicious_api_xrefs\":").append(arr(apiXrefs)).append(",");
        j.append("\"strings\":{");
        j.append("\"urls\":").append(strArr(urls)).append(",");
        j.append("\"ips\":").append(strArr(ips)).append(",");
        j.append("\"registry\":").append(strArr(reg)).append(",");
        j.append("\"paths\":").append(strArr(paths)).append(",");
        j.append("\"suspicious\":").append(strArr(susStr)).append(",");
        j.append("\"total_defined\":").append(stringCount);
        j.append("},");
        j.append("\"dynamic_hints\":").append(arr(hints));
        j.append("}");

        try (PrintWriter w = new PrintWriter(new FileWriter(outPath))) {
            w.print(j.toString());
        }
        println("NemesisStatic: wrote " + outPath);
    }

    static String anom(String type, String addr, String func, String detail, String why) {
        return "{\"type\":\"" + esc(type) + "\",\"addr\":\"" + esc(addr) + "\",\"func\":\""
                + esc(func) + "\",\"detail\":\"" + esc(detail) + "\",\"why\":\"" + esc(why) + "\"}";
    }
    static String hint(String kind, String where, String why) {
        return "{\"kind\":\"" + esc(kind) + "\",\"where\":\"" + esc(where) + "\",\"why\":\"" + esc(why) + "\"}";
    }
}
