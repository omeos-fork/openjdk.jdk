package nmt;

import java.nio.file.Paths;

public class Main
{
	public static void main(String[] args) throws Exception
	{
		boolean DEBUG = false;
		if (DEBUG)
		{
			System.out.println("\n\n\n");
			for (int i = 0; i < args.length; i++)
			{
				System.out.println("args["+i+"]: \""+args[i]+"\"");
			}
			System.out.println("");
		}

		if (args.length == 3)
    {
      System.out.println("Running as benchmark recorder");
      String mode = args[0];
      String wdir_path = Paths.get(args[1]).toAbsolutePath().toString();
      System.out.println(" wdir_path:"+wdir_path);
      String jdk_bin_path = Paths.get(args[2]).toAbsolutePath().toString();
      System.out.println(" jdk_bin_path:"+jdk_bin_path);
      BenchmarkRecorder.record(mode, wdir_path, jdk_bin_path);
    }
    else if (args.length == 4)
		{
      System.out.println("Running as benchmark analyzer");
			String mode = args[0];
      System.out.println(" mode:"+mode);
      String java_path = Paths.get(args[1]).toAbsolutePath().toString();
      System.out.println(" java_path:"+java_path);
      String path = Paths.get(args[2]).toAbsolutePath().toString();
      System.out.println(" path:"+path);
      long pid = Long.parseLong(args[3]);
      System.out.println(" pid:"+pid);
      Benchmark.examine_recording_with_pid(mode, java_path, pid, path);
		}
	}
}
