import java.io.BufferedWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.stream.Collectors;

class FindNonNullFeaturesThread extends Thread {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";
    private Thread t;
    private final String threadName;
    private final String packetProtocol;
    private final String current_field;
    private final ArrayList<String> pcapnames_train;
    private final ArrayList<String> pcapnames_test;
    private final String work_folder;
    private final BufferedWriter output_text;
    private final String protocol;
    private final int pos_of_current_field;
    private final int no_of_fields;
    private final boolean useStreamFeatures;
    private final ArrayList<String> classes;
    private final int no_of_os_instances_train;
    private final int no_of_os_instances_test;

    FindNonNullFeaturesThread(ArrayList<String> classes, int no_of_os_instances_train, int no_of_os_instances_test, String protocolToFilter, String protocol, String current_field_input, ArrayList<String> pcapnames_train, ArrayList<String> pcapnames_test, String work_folder, BufferedWriter output_text, int pos_of_current_field, int no_of_fields, boolean useStreamFeatures) {
        this.current_field = current_field_input;
        this.pcapnames_train = pcapnames_train;
        this.pcapnames_test = pcapnames_test;
        this.work_folder = work_folder;
        this.output_text = output_text;
        this.pos_of_current_field = pos_of_current_field;
        this.no_of_fields = no_of_fields;
        this.packetProtocol = protocolToFilter;
        this.useStreamFeatures = useStreamFeatures;
        this.protocol = protocol;
        this.classes = classes;
        this.no_of_os_instances_train = no_of_os_instances_train;
        this.no_of_os_instances_test = no_of_os_instances_test;

        threadName = current_field.split(",")[0];
    }

    // check this
    public void run() {
        boolean write_to_file = false;
        boolean empty = true;
        String featureName = current_field.split(",")[0];

        if (current_field.split("_")[0].equals("stream") && useStreamFeatures)
            write_to_file = true;
        else {
            int noOfNonEmptyInstances = 0;

            // train
            for (int i = 0; i < no_of_os_instances_train; i++) {
                for (int j = 0; j < classes.size(); j++) {
                    if (!isEmpty(classes.get(j) + "_" + no_of_os_instances_train, featureName, "/pcap_files/")) {
                        noOfNonEmptyInstances++;
                        break;
                    }
                }
            }

            for (int i = 0; i < no_of_os_instances_test; i++) {
                for (int j = 0; j < classes.size(); j++) {
                    if (!isEmpty(classes.get(j) + "_" + no_of_os_instances_test, featureName, "/pcap_files_test/")) {
                        noOfNonEmptyInstances++;
                        break;
                    }
                }
            }

            if (noOfNonEmptyInstances == (no_of_os_instances_train + no_of_os_instances_test))
                empty = false;

            if (!empty)
                write_to_file = true;
        }

        if (write_to_file) {
            synchronized(output_text) {
                try {
                    output_text.write(current_field);
                    output_text.newLine();
                    output_text.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        System.out.println(ANSI_BLUE + "Feature: " + ANSI_GREEN + featureName + ANSI_BLUE + " (" + pos_of_current_field + "/" + no_of_fields + ")" + ANSI_RESET);
    }

    public boolean isEmpty(String current_os, String featureName, String path) {
        ArrayList<String> output = new ArrayList<>();
        String command;
        if (packetProtocol == null) {
            if (!protocol.equals("all"))
                command = "tshark -n -r " + work_folder + path + current_os + " -Y 'frame.protocols contains \"" + protocol.split("_")[protocol.split("_").length-1] + "\"' -Tfields -e " + featureName;
            else
                command = "tshark -n -r " + work_folder + path + current_os + " -Tfields -e " + featureName;
        }
        else {
            if (!protocol.equals("all"))
                command = "tshark -n -r " + work_folder + path + current_os + " -Y 'frame.protocols contains \"" + protocol.split("_")[protocol.split("_").length-1] + "\" and " + packetProtocol + " ' -Tfields -e " + featureName;
            else
                command = "tshark -n -r " + work_folder + path + current_os + " -Y '" + packetProtocol + "' -Tfields -e " + featureName;
        }
        output.addAll(new ExecuteSystemCommand().execute(command, false));

        // Check if the feature is null
        // Get unique entries
        ArrayList<String> listDistinct = (ArrayList<String>) output.stream().distinct().collect(Collectors.toList());

//        System.out.println(work_folder + path + current_os + " -> " + featureName + " -> " + listDistinct.size());

        if (listDistinct.size() == 0)
            return true;

        if (listDistinct.size() == 1 && listDistinct.get(0).trim().length() == 0)
            return true;

        return false;
    }

    public void start () {
        if (t == null) {
            t = new Thread (this, threadName);
            t.start ();
        }
    }
}