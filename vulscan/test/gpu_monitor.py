import logging
import subprocess
import time


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("gpu_monitor.log"), logging.StreamHandler()],
)


def get_gpu_info():
    """
    get_gpu_info: get GPU information using nvidia-smi
    """
    try:
        # query GPU memory usage
        cmd = [
            "nvidia-smi",
            "--query-gpu=index,memory.total,memory.free,memory.used",
            "--format=csv,noheader,nounits",
        ]
        output = subprocess.check_output(cmd).decode("utf-8").strip()

        gpus = []
        for line in output.split("\n"):
            index, total, free, used = map(float, line.split(","))
            free_percentage = (free / total) * 100
            gpus.append(
                {
                    "index": int(index),
                    "total_memory": total,
                    "free_memory": free,
                    "used_memory": used,
                    "free_percentage": free_percentage,
                }
            )
        return gpus
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running nvidia-smi: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return None


def check_gpu_condition(gpus, gpu_num, percentage=90):
    """
    check_gpu_condition: check if the condition is met to run the command
    return：(bool, list) - (condition_met, available_gpus)
    """
    if not gpus or len(gpus) < gpu_num:
        return False, []

    # get the indices of GPUs with >90% free memory
    available_gpus = [
        gpu["index"] for gpu in gpus if gpu["free_percentage"] > percentage
    ]

    if len(available_gpus) >= gpu_num:
        # only return the first gpu_num GPUs
        return True, available_gpus[:gpu_num]
    return False, []


def run_command(command, gpu_indices):
    """
    ，add CUDA_VISIBLE_DEVICES before the command
    """
    start_time = time.time()
    try:
        # convert the list of GPU indices to a comma-separated string
        gpu_list = ",".join(map(str, gpu_indices))

        # CUDA_VISIBLE_DEVICES
        env = f"CUDA_VISIBLE_DEVICES={gpu_list}"
        full_command = f"{env} {command}"

        logging.info(f"Running command with GPUs {gpu_list}: {full_command}")

        subprocess.run(full_command, shell=True, check=True)
        logging.info(f"Successfully executed command: {full_command}")
        return True
    except subprocess.CalledProcessError as e:
        if time.time() - start_time > 600:
            exit(1)
        logging.error(f"Error executing command: {e}")
        return False


def main(command_to_run, check_interval=60, gpu_num=4, percentage=90):
    """
    command_to_run: the command to run when conditions are met
    check_interval: check interval in seconds (default: 60)
    """
    logging.info(
        f"Starting GPU monitor. Will execute: \n{' '.join(command_to_run.split())}"
    )
    try_num = 0

    print(
        f"Checking every {check_interval} seconds to find {gpu_num} GPUs with >{percentage}% free memory",
        end="",
        flush=True,
    )

    while True:
        try:
            try_num += 1
            print(
                f"\rChecking every {check_interval} seconds to find {gpu_num} GPUs with >{percentage}% free memory, trying {try_num} times",
                end="",
                flush=True,
            )

            gpus = get_gpu_info()

            if gpus:
                # record GPU information
                for gpu in gpus:
                    logging.debug(
                        f"GPU {gpu['index']}: {gpu['free_percentage']:.2f}% free"
                    )

                condition_met, available_gpus = check_gpu_condition(
                    gpus, gpu_num, percentage
                )
                if condition_met:
                    print()
                    logging.info(
                        f"Found {gpu_num} GPUs with >90% free memory: {available_gpus}"
                    )
                    if run_command(command_to_run, available_gpus):
                        logging.info("Command executed successfully, exiting monitor")
                        break
                    else:
                        logging.error("Command failed, continuing monitoring")

            time.sleep(check_interval)

        except KeyboardInterrupt:
            print()
            logging.info("Received keyboard interrupt, stopping monitor")
            break
        except Exception as e:
            print()
            logging.error(f"Unexpected error in main loop: {e}")
            time.sleep(check_interval)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Monitor GPU usage and execute command when conditions are met"
    )
    parser.add_argument(
        "command", help="Command to execute when GPU conditions are met"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Check interval in seconds (default: 60)",
    )
    parser.add_argument("--gpu_num", type=int, help="Number of GPUs to use")
    parser.add_argument(
        "--percentage",
        type=int,
        default=90,
        help="Minimum percentage of free memory to consider (default: 90)",
    )

    args = parser.parse_args()

    main(args.command, args.interval, args.gpu_num, args.percentage)
