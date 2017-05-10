module.exports = function(grunt) {

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    concat: {
      options: {
        separator: ';'
      },
      dist: {
        src: ['gen_ie.js'],
        dest: 'dist/<%= pkg.name %>.js'
      }
    },
    uglify: {
      options: {
        banner: '/*! <%= pkg.name %> <%= grunt.template.today("dd-mm-yyyy") %> */\n'
      },
      dist: {
        files: {
          'dist/<%= pkg.name %>.min.js': ['<%= concat.dist.dest %>']
        }
      }
    },
    qunit: {
      files: ['gen_ie.html']
    },
    jshint: {
      files: ['gen_ie.js'],
      options: {
        // options here to override JSHint defaults
	      reporterOutput: "",
        globals: {
          jQuery: true,
          console: true,
          module: true,
          document: true
        }
      }
    },
    watch: {
      files: ['<%= jshint.files %>'],
      tasks: ['jshint', 'qunit']
    },
    karma: {
      options: {
        configFile: 'karma.conf.js'
      },
      ci: {
        
      },
      dev: {
        reporters: 'dots',
        browsers: ['Chrome']
      }
    }
  });

  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-qunit');
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-karma');

//  grunt.registerTask('test', ['jshint', 'qunit', 'karma:ci']);
  grunt.registerTask('test', ['karma:ci']);

  grunt.registerTask('default', ['jshint', 'qunit', 'concat', 'uglify']);

};
