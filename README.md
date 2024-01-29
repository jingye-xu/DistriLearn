# DistriLearn: Unified Deployment using ROS

When using ROS, you always need to have (and therefore create) a workspace for your project. 

This NIDS branch is already a ROS workspace. Within the `src` folder is the NIDS package for this project. All entrypoints are already set up, so the only thing needed to do is edit the code and/or build the workspace and source the overlay. ROS can be divided into two primary working components:
- <b>Underlay</b>: The installed ROS environment which you `source` its setup script prior to initiating any work using ROS itself. This will typically be located in `/opt/ros/<ros_version>/setup.bash`; This will provide our environment with the ROS dependencies. 
- <b>Overlay</b>: This is our workspace, which we also need to source.

After any edits you make, you must build the workspace (After building the workspace, of course) using `colcon`. Then you can execute `source` on your workspace directory under the `./install/setup.bash` directory of the workspace. I usually prefer to source the underlay and overlay after each build.


When installing ROS, you may be inclined to use Ubuntu. We can debootstrap Ubuntu, but Debian is also plausible since Ubuntu is based on Debian (you can find the chart). To add the ROS repository to debian, you need to use the correct ditribution. To see the distributions, check here: http://packages.ros.org/ros2. For instance, if I am using Debian 12 (Bookworm), I would use `http://packages.ros.org/ros2/ubuntu bookworm main`. This can be interpolated as such: `http://packages.ros.org/ros2 $(lsb_release -cs) main`. For our research, we are deploying on smaller devices. Pay attention to which Linux you are using. It is better to install ROS from source on Debian, than the binaries. If you build from source, the underlay will be different!



NOTE: Run the code from the root DistriLearn workspace!
