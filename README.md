# DistriLearn: Unified Deployment using ROS

When using ROS, you always need to have (and therefore create) a workspace for your project. 

This NIDS branch is already a ROS workspace. ROS can be divided into two primary working components:
- <b>Underlay</b>: The installed ROS environment which you `source` its setup script prior to initiating any work using ROS itself. This will typically be located in `/opt/ros/<ros_version>/setup.bash`; This will provide our environment with the ROS dependencies. 
- <b>Overlay</b>: This is our workspace, which we also need to source.

After any edits you make, you must build the workspace using `colcon`. Then you can execute `source` on your workspace directory under the `./install/setup.bash` directory of the workspace. I usually prefer to source the underlay and overlay after each build.
