public class StringBuf {

    private char[] arr;

    public StringBuf() {
        this.arr = new char[32];
    }

    public StringBuf(int capacity) {
        this.arr = new char[capacity];
    }

    public StringBuf append(String str) {
        int len = str.length();
        int newCount = length() + len;
        if (newCount > arr.length * 0.75) {
            char[] newArr = new char[arr.length + len];
            System.arraycopy(arr, 0, newArr, 0, arr.length);
            arr = newArr;
        }
        str.getChars(0, len, arr, length());
        return this;
    }

    public int length() {
        return arr.length;
    }

    @Override
    public String toString() {
        return new String(arr);
    }

}
