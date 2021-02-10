package io.github.t4skforce.deepviolet.json;

import java.util.HashMap;

public class CipherMapJson extends HashMap<String, CipherMapClassificationsJson> {
    private static final long serialVersionUID = 5660722767135755938L;

    public CipherMapJson() {

    }

    public CipherMapJson(String hexName, CipherMapClassificationsJson clazz) {
        put(hexName, clazz);
    }

}
