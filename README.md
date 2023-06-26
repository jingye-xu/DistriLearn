# DistriLearn: Unified Deployment using ROS

When using ROS, you always need to have (and therefore create) a workspace for your project. 

This NIDS branch is already a ROS workspace. ROS can be divided into two primary working components:
- <b>Underlay</b>: The installed ROS environment which you `source` its setup script prior to initiating any work using ROS itself. This will typically be located in `/opt/ros/<ros_version>/setup.bash`; This will provide our environment with the ROS dependencies. 
- <b>Overlay</b>: This is our workspace, which we also need to source.

After any edits you make, you must build the workspace using `colcon`. Then you can execute `source` on your workspace directory under the `./install/setup.bash` directory of the workspace. I usually prefer to source the underlay and overlay after each build.


When installing ROS, you may be inclined to use Ubuntu. We can debootstrap Ubuntu, but Debian is also plausible. To add the ROS repository to debian, you need to use the correct ditribution. To see the distributions, check here: http://packages.ros.org/ros2. For instance, if I am using Debian 12 (Bookworm), I would use `http://packages.ros.org/ros2 bookwork main`. For our research, we are deploying on smaller devices. As such, we want the <b>base</b> ROS without RViz, etc.


