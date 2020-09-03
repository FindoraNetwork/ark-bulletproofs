pipeline {

  environment {
    dockerRepo = 'https://563536162678.dkr.ecr.us-west-2.amazonaws.com'
    dockerCreds = 'ecr:us-west-2:aws-jenkins'
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
        not {
          changeRequest()
        }
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
