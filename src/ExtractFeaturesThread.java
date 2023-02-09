import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

class ExtractFeaturesThread extends Thread {
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
    private String threadName;
    private CountDownLatch latch;
    private String current_class;
    private String protocol_file_path;
    private String tshark_attributes;
    private String source_file;
    private String pcap_file;
    private String packetProtocol;
    private String protocol;
    private boolean useDerivedFeatures;
    private ArrayList<String> derivedFeaturesSuffixConsider;
    private ArrayList<String> derivedFeaturesSuffixIgnore;
    private ArrayList<String> derivedFeaturesSuffixInclude;

    ExtractFeaturesThread(String packetProtocol, String protocol, CountDownLatch latch, String current_class, String protocol_file_path, String tshark_attributes, String source_file, String pcap_file, boolean useDerivedFeatures, ArrayList<String> derivedFeaturesSuffixConsider, ArrayList<String> derivedFeaturesSuffixIgnore, ArrayList<String> derivedFeaturesSuffixInclude) {
        this.latch = latch;
        this.current_class = current_class;
        this.protocol_file_path = protocol_file_path;
        this.tshark_attributes = tshark_attributes;
        this.source_file = source_file;
        this.pcap_file = pcap_file;
        this.packetProtocol = packetProtocol;
        this.useDerivedFeatures = useDerivedFeatures;
        this.derivedFeaturesSuffixConsider = derivedFeaturesSuffixConsider;
        this.derivedFeaturesSuffixIgnore = derivedFeaturesSuffixIgnore;
        this.derivedFeaturesSuffixInclude = derivedFeaturesSuffixInclude;
        this.protocol = protocol;
        threadName = current_class;
    }

    public void run() {
        new File(protocol_file_path).mkdirs(); // create a dedicated folder for the protocol

        // Extract features
        new OSExtractFeatures().extract(packetProtocol, protocol, tshark_attributes, source_file, pcap_file, current_class, useDerivedFeatures, derivedFeaturesSuffixConsider, derivedFeaturesSuffixIgnore, derivedFeaturesSuffixInclude);

        // Remove repeated examples from each examples file
        deleteDuplicates(source_file, source_file + "_uniq");

        new File(source_file).delete();

//        // Remove repeated examples from each examples file
//        deleteDuplicates(source_file, source_file + "_temp");
//        new File(source_file).delete();
//        // Randomly sort the contents of the files
//        sort_text_file(source_file + "_temp", source_file + "_uniq");
//        new File(source_file + "_temp").delete();

        System.out.println(ANSI_BLUE + "Class: " + ANSI_RED + current_class + ANSI_RESET);
        latch.countDown();
    }

    public void start() {
        if (t == null) {
            t = new Thread (this, threadName);
            t.start ();
        }
    }

    // Deletes duplicate lines in a file
    public void deleteDuplicates(String input_filename, String output_filename) {
        try {
            BufferedReader in = new BufferedReader(new FileReader(input_filename));
            Set<String> lines = new LinkedHashSet<>();

            for (String line; (line = in.readLine()) != null;)
                lines.add(line); // does nothing if duplicate is already added

            PrintWriter out = new PrintWriter(output_filename);

            for (String line : lines)
                out.println(line);

            in.close();
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void sortTextFile(String input, String output) {
        BufferedReader reader = null;
        BufferedWriter writer = null;

        //Create an ArrayList object to hold the lines of input file
        ArrayList<String> lines = new ArrayList<>();

        try {
            //Creating BufferedReader object to read the input file
            reader = new BufferedReader(new FileReader(input));

            //Reading all the lines of input file one by one and adding them into ArrayList
            String currentLine = reader.readLine();

            while (currentLine != null) {
                lines.add(currentLine);
                currentLine = reader.readLine();
            }

            // Sorting the ArrayList
            Collections.sort(lines);

            // Creating BufferedWriter object to write into output file
            writer = new BufferedWriter(new FileWriter(output));

            // Writing sorted lines into output file
            for (String line : lines) {
                writer.write(line);
                writer.newLine();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            //Closing the resources
            try {
                if (reader != null)
                    reader.close();

                if(writer != null)
                    writer.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
