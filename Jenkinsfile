pipeline {

  environment {
    dockerRepo = 'https://nexus.findora.org'
    dockerCreds = 'nexus'
    dockerName = 'bulletproofs'
  }

  agent any

  stages {
    stage('Build') {
      steps {
        script {
          docker.withRegistry( dockerRepo, dockerCreds ) {
            buildImage = docker.build( dockerName + ":" + env.BRANCH_NAME, '--pull .')
          }
        }
      }
    }

    stage('Push') {
      when {
        branch 'master'
      }
      steps {
        script {
          docker.withRegistry( dockerRepo, dockerCreds ) {
            dockerImage = docker.build( dockerName + ":" + env.BRANCH_NAME, '--pull .')
            dockerImage.push()
          }
        }
      }
    }

  }

}
