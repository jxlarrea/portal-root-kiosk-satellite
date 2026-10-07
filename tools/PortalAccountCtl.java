import android.accounts.Account;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.os.IBinder;
import android.os.Looper;
import android.os.Process;

import java.io.File;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Local AccountManager cleanup for Portal user-account types. */
public final class PortalAccountCtl {
    private static final Set<String> META_ACCOUNT_TYPES = new HashSet<>(
            Arrays.asList(
                    "com.facebook.aloha.sso",
                    "com.facebook.aloha.pl",
                    "com.facebook.aloha.privowner"));

    private static String callerPackage() {
        if (Process.myUid() == 2000) {
            return "com.android.shell";
        }
        if (Process.myUid() == 1000) {
            return "android";
        }
        return "com.facebook.alohaservices.alohausers";
    }

    private static int removeLocalIdentityRows() throws Exception {
        int total = 0;
        Set<String> targets = new HashSet<>(Arrays.asList(
                "device_accounts",
                "device_owners",
                "aloha_proxy_user",
                "aloha_device_owners"));
        Set<String> found = new HashSet<>();
        String[] databaseDirectories = {
                "/data/user/0/com.facebook.alohaservices.alohausers/databases",
                "/data/user_de/0/com.facebook.alohaservices.alohausers/databases",
        };
        for (String directoryName : databaseDirectories) {
            File directory = new File(directoryName);
            File[] files = directory.listFiles();
            if (files == null) {
                continue;
            }
            for (File file : files) {
                String name = file.getName();
                if (!file.isFile() || name.endsWith("-wal")
                        || name.endsWith("-shm") || name.endsWith("-journal")) {
                    continue;
                }
                SQLiteDatabase database;
                try {
                    database = SQLiteDatabase.openDatabase(
                            file.getAbsolutePath(), null,
                            SQLiteDatabase.OPEN_READONLY);
                } catch (SQLiteException ignored) {
                    continue;
                }
                Set<String> present = new HashSet<>();
                try {
                    for (String table : targets) {
                        Cursor cursor = database.rawQuery(
                                "SELECT 1 FROM sqlite_master "
                                        + "WHERE type='table' AND name=?",
                                new String[] {table});
                        boolean exists;
                        try {
                            exists = cursor.moveToFirst();
                        } finally {
                            cursor.close();
                        }
                        if (!exists) {
                            continue;
                        }
                        present.add(table);
                    }
                } catch (RuntimeException ignored) {
                    // These directories can contain non-SQLite auxiliary files.
                    // A bad candidate must not abort cleanup of the real stores.
                    System.out.println("PORTAL_META_LOCAL_SKIP database="
                            + file.getAbsolutePath() + " reason=not_sqlite");
                    continue;
                } finally {
                    database.close();
                }
                if (present.isEmpty()) {
                    continue;
                }
                database = SQLiteDatabase.openDatabase(
                        file.getAbsolutePath(), null,
                        SQLiteDatabase.OPEN_READWRITE);
                database.beginTransaction();
                try {
                    for (String table : present) {
                        int count = database.delete(table, null, null);
                        total += count;
                        System.out.println("PORTAL_META_LOCAL_DELETE database="
                                + file.getAbsolutePath() + " table=" + table
                                + " rows=" + count);
                    }
                    database.setTransactionSuccessful();
                    found.addAll(present);
                } finally {
                    database.endTransaction();
                    database.close();
                }
            }
        }
        if (!found.containsAll(targets)) {
            targets.removeAll(found);
            throw new IllegalStateException(
                    "identity tables not found: " + targets);
        }
        return total;
    }

    private static Object accountService() throws Exception {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        Method getService = serviceManager.getDeclaredMethod(
                "getService", String.class);
        IBinder binder = (IBinder) getService.invoke(null, "account");
        if (binder == null) {
            throw new IllegalStateException("account service is absent");
        }
        Class<?> stub = Class.forName("android.accounts.IAccountManager$Stub");
        Method asInterface = stub.getDeclaredMethod("asInterface", IBinder.class);
        return asInterface.invoke(null, binder);
    }

    private static Account[] getAccounts(Object service) throws Exception {
        Method method = service.getClass().getMethod(
                "getAccounts", String.class, String.class);
        return (Account[]) method.invoke(service, null, callerPackage());
    }

    private static boolean removeAccount(Object service, Account account)
            throws Exception {
        Method method = service.getClass().getMethod(
                "removeAccountExplicitly", Account.class);
        return (Boolean) method.invoke(service, account);
    }

    private static boolean isMetaAccount(Account account) {
        return META_ACCOUNT_TYPES.contains(account.type);
    }

    public static void main(String[] args) {
        String action = args.length == 0 ? "status" : args[0];
        if (!action.equals("status") && !action.equals("remove")
                && !action.equals("remove-accounts-only")) {
            System.err.println(
                    "usage: PortalAccountCtl [status|remove|remove-accounts-only]");
            System.exit(64);
        }

        try {
            Object service = accountService();
            Account[] before = getAccounts(service);
            int found = 0;
            int removed = 0;
            for (Account account : before) {
                if (!isMetaAccount(account)) {
                    continue;
                }
                found++;
                System.out.println("PORTAL_META_ACCOUNT_FOUND type="
                        + account.type + " name=" + account.name);
                if (!action.equals("status")) {
                    boolean ok = removeAccount(service, account);
                    System.out.println("PORTAL_META_ACCOUNT_REMOVE type="
                            + account.type + " name=" + account.name
                            + " ok=" + ok);
                    if (!ok) {
                        System.exit(2);
                    }
                    removed++;
                }
            }

            int remaining = 0;
            for (Account account : getAccounts(service)) {
                if (isMetaAccount(account)) {
                    remaining++;
                }
            }
            int localRows = action.equals("remove")
                    ? removeLocalIdentityRows() : 0;
            System.out.println("PORTAL_META_ACCOUNT_CTL_OK action=" + action
                    + " found=" + found + " removed=" + removed
                    + " remaining=" + remaining + " local_rows=" + localRows);
            if (!action.equals("status") && remaining != 0) {
                System.exit(3);
            }
        } catch (Throwable t) {
            System.err.println("PORTAL_META_ACCOUNT_CTL_ERROR " + t);
            Throwable cause = t.getCause();
            if (cause != null) {
                System.err.println("caused by: " + cause);
            }
            t.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
