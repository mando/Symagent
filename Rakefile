$BASE_DIR           = File.expand_path(Rake::original_dir)
$LIB_INSTALL_DIR    = $BASE_DIR
$AGENT_INSTALL_DIR  = $BASE_DIR
$CONF_DIR           = $BASE_DIR + '/etc'
$LOG_DIR            = $BASE_DIR + '/log'
$HOST_NAME          = "localhost"

# Load symagent and libsymbiot Rakefiles
load Rake::original_dir + '/library/Rakefile'
load Rake::original_dir + '/agents/symagent/Rakefile'

# Load Plugin Rakefiles
Dir[(Rake::original_dir + '/agents/symagent/plugins/*/Rakefile').to_s].each { |r| load r }

# Project list
projects = ['libsymbiot', 'symagent', 'effector', 'logwatcher', 'maclookup', 'network', 'nmap', 'processes', 'snort_mysql']

desc "Bootstrap *"
task :bootstrap do
    puts "> Bootstrapping - all..."
    projects.each do |proj|
        subtask = proj + ":bootstrap"
        Rake::Task[subtask].invoke
    end
    puts "> Bootstrapping - all... done"
end

desc "Clean *"
task :clean do
    puts "> Cleaning - all..."
    projects.each do |proj|
        subtask = proj + ":clean"
        Rake::Task[subtask].invoke
    end
    puts "> Cleaning - all... done"
end

desc "Build *"
task :build do
    puts "> Building - all..."
    projects.each do |proj|
        subtask = proj + ":build"
        Rake::Task[subtask].invoke
    end
    puts "> Building - all... done"
end

desc "Install *"
task :install do
    puts "> Installing - all..."
    projects.each do |proj|
        subtask = proj + ":install"
        Rake::Task[subtask].invoke
    end
    puts "> Installing - all... done"
end
